// admin-gate is the Monban plugin that gates sudo (and eventually macOS
// admin authorization dialogs) behind a FIDO2 security-key assertion.
//
// Architecture:
//
//   sudo → pam_monban.so → monban-pam-helper
//        → Unix socket in $MONBAN_PLUGIN_DIR/helper.sock
//        → admin-gate plugin (this binary)
//        → request_pin_touch RPC → Monban host
//        → PinAuth dialog in UI → FIDO2 assert → result
//        → reply propagates back down the chain to PAM
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ---------- stdio JSON-RPC (host <-> this plugin) ----------

type message struct {
	ID     string          `json:"id,omitempty"`
	Type   string          `json:"type"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type helloResult struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Hooks    []string `json:"hooks"`
	Provides []any    `json:"provides"`
	Ready    bool     `json:"ready"`
}


// ---------- helper protocol (this plugin <-> pam-helper over Unix socket) ----------

type helperRequest struct {
	User    string `json:"user"`
	Service string `json:"service"`
	// Pin, when non-empty, comes from /dev/tty in the helper (terminal
	// sudo). Plugin forwards it via auth.assert_with_pin and we never
	// touch the Monban UI. Empty PIN means the helper had no TTY →
	// fall back to the UI-driven request_pin_touch flow.
	Pin string `json:"pin,omitempty"`
}

type helperResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ---------- state ----------

var (
	stdoutMu   sync.Mutex                   // serialises writes to host
	pending    = map[string]chan *message{} // outstanding request_pin_touch calls keyed by request ID
	pendingMu  sync.Mutex
	listenerMu sync.Mutex
	listener   net.Listener
)

func main() {
	stdin := bufio.NewReader(os.Stdin)
	stdout := bufio.NewWriter(os.Stdout)

	for {
		line, err := stdin.ReadBytes('\n')
		if err != nil {
			_ = stdout.Flush()
			return
		}
		var in message
		if err := json.Unmarshal(line, &in); err != nil {
			continue
		}
		dispatch(stdout, &in)
	}
}

// dispatch handles one inbound host→plugin message.
func dispatch(w *bufio.Writer, in *message) {
	// Responses to requests we sent get routed to the waiting channel.
	if in.Type == "response" || in.Type == "error" {
		pendingMu.Lock()
		ch, ok := pending[in.ID]
		if ok {
			delete(pending, in.ID)
		}
		pendingMu.Unlock()
		if ok {
			ch <- in
		}
		return
	}

	switch in.Method {
	case "hello":
		res, _ := json.Marshal(helloResult{
			Name:     "admin-gate",
			Version:  "0.1.0",
			Hooks:    []string{"on:app_started", "on:app_shutdown"},
			Provides: []any{},
			Ready:    true,
		})
		writeHost(w, message{ID: in.ID, Type: "response", Result: res})

		// Open the helper socket right after hello (rather than on
		// on:app_started) so the SecurityAgent bundle can connect the
		// moment Monban's plugin host is up — BEFORE Wails' main
		// window appears. This eliminates the cold-start race where
		// the window would render the default lock view before a
		// queued pin-touch request made it over.
		if err := startSocketListener(w); err != nil {
			logLine(w, "error", "socket listener: "+err.Error())
		}

	case "on:app_started":
		logLine(w, "info", "admin-gate online")

	case "on:app_shutdown":
		stopSocketListener(w)
		logLine(w, "info", "admin-gate offline")

	case "settings.apply":
		// No settings surface today — accept and no-op so host-side
		// plumbing stays happy if any are sent.
		res, _ := json.Marshal(map[string]any{"ok": true})
		writeHost(w, message{ID: in.ID, Type: "response", Result: res})

	case "shutdown":
		stopSocketListener(w)
		_ = w.Flush()
		os.Exit(0)

	default:
		if in.Type == "request" {
			writeHost(w, message{
				ID:    in.ID,
				Type:  "error",
				Error: &rpcError{Code: -32601, Message: "method not supported"},
			})
		}
	}
}

// ---------- host stdout helpers ----------

func writeHost(w *bufio.Writer, m message) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	_, _ = w.Write(b)
	_ = w.WriteByte('\n')
	_ = w.Flush()
}

func logLine(w *bufio.Writer, level, msg string) {
	params, _ := json.Marshal(map[string]string{"level": level, "message": msg})
	writeHost(w, message{Type: "notify", Method: "log", Params: params})
}

// assertWithPin hands a user-supplied PIN up to the host via the
// auth.assert_with_pin RPC. The host does the FIDO2 assertion (which
// blocks until the user touches their key). The plugin process itself
// never handles libfido2 — keeps the trust boundary at Monban.
func assertWithPin(w *bufio.Writer, pin string, timeout time.Duration) (bool, error) {
	id := fmt.Sprintf("aa-%d", time.Now().UnixNano())
	ch := make(chan *message, 1)

	pendingMu.Lock()
	pending[id] = ch
	pendingMu.Unlock()
	defer func() {
		pendingMu.Lock()
		delete(pending, id)
		pendingMu.Unlock()
	}()

	params, _ := json.Marshal(map[string]string{"pin": pin})
	writeHost(w, message{ID: id, Type: "request", Method: "auth.assert_with_pin", Params: params})

	select {
	case resp := <-ch:
		if resp.Type == "error" || resp.Error != nil {
			if resp.Error != nil {
				return false, fmt.Errorf("%s", resp.Error.Message)
			}
			return false, fmt.Errorf("host error")
		}
		var r struct {
			OK bool `json:"ok"`
		}
		_ = json.Unmarshal(resp.Result, &r)
		return r.OK, nil
	case <-time.After(timeout):
		return false, fmt.Errorf("auth.assert_with_pin timed out")
	}
}

// requestPinTouch sends a request_pin_touch RPC to the host and blocks
// until it returns or times out.
func requestPinTouch(w *bufio.Writer, service, user string, timeout time.Duration) (bool, error) {
	id := fmt.Sprintf("pt-%d", time.Now().UnixNano())
	ch := make(chan *message, 1)

	pendingMu.Lock()
	pending[id] = ch
	pendingMu.Unlock()
	defer func() {
		pendingMu.Lock()
		delete(pending, id)
		pendingMu.Unlock()
	}()

	params, _ := json.Marshal(map[string]string{
		"title":    fmt.Sprintf("Authenticate for %s", service),
		"subtitle": fmt.Sprintf("%s@%s", user, service),
	})
	writeHost(w, message{ID: id, Type: "request", Method: "request_pin_touch", Params: params})

	select {
	case resp := <-ch:
		if resp.Type == "error" || resp.Error != nil {
			if resp.Error != nil {
				return false, fmt.Errorf("%s", resp.Error.Message)
			}
			return false, fmt.Errorf("host error")
		}
		var r struct {
			OK bool `json:"ok"`
		}
		_ = json.Unmarshal(resp.Result, &r)
		return r.OK, nil
	case <-time.After(timeout):
		return false, fmt.Errorf("request_pin_touch timed out")
	}
}

// ---------- Unix socket listener ----------

func socketPath() string {
	dir := os.Getenv("MONBAN_PLUGIN_DIR")
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "helper.sock")
}

func startSocketListener(w *bufio.Writer) error {
	path := socketPath()
	if path == "" {
		return fmt.Errorf("MONBAN_PLUGIN_DIR not set")
	}
	// Clean up a stale socket file if one is present.
	_ = os.Remove(path)

	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		logLine(w, "warn", "chmod socket: "+err.Error())
	}

	listenerMu.Lock()
	listener = l
	listenerMu.Unlock()

	logLine(w, "info", "helper socket listening at "+path)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return // listener closed
			}
			go handleHelperConn(w, conn)
		}
	}()
	return nil
}

func stopSocketListener(w *bufio.Writer) {
	listenerMu.Lock()
	l := listener
	listener = nil
	listenerMu.Unlock()
	if l == nil {
		return
	}
	_ = l.Close()
	if path := socketPath(); path != "" {
		_ = os.Remove(path)
	}
	logLine(w, "info", "helper socket closed")
}

// handleHelperConn handles one connection from monban-pam-helper.
//
// Wire protocol: a single JSON line request, a single JSON line response.
// The helper closes the connection after reading the response.
func handleHelperConn(w *bufio.Writer, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Minute))

	var req helperRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeHelper(conn, helperResponse{Error: "bad request: " + err.Error()})
		return
	}
	if req.User == "" {
		writeHelper(conn, helperResponse{Error: "missing user"})
		return
	}

	hasPin := req.Pin != ""
	logLine(w, "info", fmt.Sprintf("helper auth request: user=%s service=%s tty=%v", req.User, req.Service, hasPin))

	var (
		ok  bool
		err error
	)
	if hasPin {
		logLine(w, "info", "→ assert with TTY-supplied PIN (FIDO2 will wait for touch)")
		ok, err = assertWithPin(w, req.Pin, 2*time.Minute)
	} else {
		logLine(w, "info", "→ no TTY, requesting UI PIN prompt")
		ok, err = requestPinTouch(w, req.Service, req.User, 2*time.Minute)
	}
	if err != nil {
		logLine(w, "warn", "auth failed: "+err.Error())
		writeHelper(conn, helperResponse{Error: err.Error()})
		return
	}
	logLine(w, "info", fmt.Sprintf("← auth result: ok=%v", ok))
	writeHelper(conn, helperResponse{OK: ok})
}

func writeHelper(conn io.Writer, resp helperResponse) {
	b, _ := json.Marshal(resp)
	_, _ = conn.Write(append(b, '\n'))
}
