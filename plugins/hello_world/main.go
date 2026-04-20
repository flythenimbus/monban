// hello-world is the reference / smoke-test plugin for the Monban plugin
// host. It implements the minimum hello handshake and echoes log lines when
// on:app_started and on:app_shutdown notifies arrive.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type message struct {
	ID     string          `json:"id,omitempty"`
	Type   string          `json:"type"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

type helloResult struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Hooks    []string `json:"hooks"`
	Provides []any    `json:"provides"`
	Ready    bool     `json:"ready"`
}

func main() {
	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var in message
		if err := json.Unmarshal(line, &in); err != nil {
			continue
		}
		switch in.Method {
		case "hello":
			res, _ := json.Marshal(helloResult{
				Name:     "hello-world",
				Version:  "0.1.0",
				Hooks:    []string{"on:app_started", "on:app_shutdown"},
				Provides: []any{},
				Ready:    true,
			})
			_ = write(w, message{ID: in.ID, Type: "response", Result: res})
		case "on:app_started":
			logLine(w, "info", "monban started — hello from hello-world")
		case "on:app_shutdown":
			logLine(w, "info", "monban shutting down — hello-world exiting")
		case "shutdown":
			return
		default:
			// Unknown notifies are ignored; unknown requests get an
			// error response so the host doesn't hang.
			if in.Type == "request" {
				errPayload, _ := json.Marshal(map[string]any{
					"code":    -32601,
					"message": fmt.Sprintf("method %q not supported", in.Method),
				})
				_ = write(w, message{ID: in.ID, Type: "error", Result: errPayload})
			}
		}
	}
}

func logLine(w *bufio.Writer, level, msg string) {
	params, _ := json.Marshal(map[string]string{"level": level, "message": msg})
	_ = write(w, message{Type: "notify", Method: "log", Params: params})
}

func write(w *bufio.Writer, m message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	if err := w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}
