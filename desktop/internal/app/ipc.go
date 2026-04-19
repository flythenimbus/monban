package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"monban/internal/monban"
)

const (
	ipcAuthTimeout    = 60 * time.Second
	ipcConnectTimeout = 5 * time.Second
)

// ipcState holds the state for a single IPC auth request.
// Only one request is processed at a time.
type ipcState struct {
	mu       sync.Mutex
	listener net.Listener
	cancel   context.CancelFunc

	// Coordination channels between the socket handler and the frontend.
	pinCh    chan string          // frontend sends PIN here
	resultCh chan error           // backend sends assertion result here
	active   bool                 // true while an auth request is being processed
	pending  *monban.IPCRequest   // current in-flight request; polled by frontend on cold start
}

// StartIPCListener begins listening for IPC auth requests on a Unix socket.
func (a *App) StartIPCListener() {
	// Ensure the config directory exists — on a clean install or after
	// config deletion the user won't have ~/.config/monban yet, and
	// net.Listen would fail. We only create the dir; registration later
	// populates credentials.json inside it.
	if err := os.MkdirAll(monban.ConfigDir(), 0700); err != nil {
		log.Printf("monban: IPC listener cannot create config dir: %v", err)
		return
	}

	monban.CleanStaleSocket()

	sockPath := monban.IPCSocketPath()

	// Config dir may be 0500 from a previous session's Lock().
	// Temporarily restore write access to create the socket.
	monban.UnlockConfigDir()
	listener, err := net.Listen("unix", sockPath)
	monban.LockConfigDir()
	if err != nil {
		log.Printf("monban: IPC listener failed: %v", err)
		return
	}

	if err := os.Chmod(sockPath, 0600); err != nil {
		log.Printf("monban: IPC socket chmod failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.ipc = &ipcState{
		listener: listener,
		cancel:   cancel,
		pinCh:    make(chan string, 1),
		resultCh: make(chan error, 1),
	}

	go a.ipcAcceptLoop(ctx)
	log.Printf("monban: IPC listening on %s", sockPath)
}

// StopIPCListener shuts down the IPC listener and cleans up the socket.
func (a *App) StopIPCListener() {
	if a.ipc == nil {
		return
	}
	a.ipc.cancel()
	_ = a.ipc.listener.Close()
	monban.CleanStaleSocket()
	a.ipc = nil
}

func (a *App) ipcAcceptLoop(ctx context.Context) {
	for {
		conn, err := a.ipc.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("monban: IPC accept error: %v", err)
				continue
			}
		}
		go a.handleIPCConn(ctx, conn)
	}
}

func (a *App) handleIPCConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(ipcAuthTimeout))

	// Serialize: only one IPC auth at a time.
	a.ipc.mu.Lock()
	if a.ipc.active {
		a.ipc.mu.Unlock()
		writeIPCResponse(conn, monban.IPCResponse{Error: "another auth request is in progress"})
		return
	}
	a.ipc.active = true
	a.ipc.mu.Unlock()

	defer func() {
		a.ipc.mu.Lock()
		a.ipc.active = false
		a.ipc.pending = nil
		a.ipc.mu.Unlock()
	}()

	// Read request
	var req monban.IPCRequest
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&req); err != nil {
		writeIPCResponse(conn, monban.IPCResponse{Error: "invalid request"})
		return
	}

	if req.Type != "auth" {
		writeIPCResponse(conn, monban.IPCResponse{Error: "unknown request type"})
		return
	}

	log.Printf("monban: IPC auth request received: service=%q user=%q", req.Service, req.User)

	// Expose the in-flight request so the frontend can pick it up on cold
	// start (before Events.On has subscribed to ipc:auth-request).
	a.ipc.mu.Lock()
	a.ipc.pending = &req
	a.ipc.mu.Unlock()

	// Exit fullscreen/kiosk mode if active — IPC auth bypasses the app's
	// own lock screen and doesn't require the app to be unlocked.
	a.ExitFullscreen()

	// Emit the event first so React can switch views while the window
	// is still hidden, then show the window after a brief render delay.
	if a.window != nil {
		log.Printf("monban: IPC emitting ipc:auth-request event")
		a.window.EmitEvent("ipc:auth-request", map[string]string{
			"user":    req.User,
			"service": req.Service,
		})
		time.Sleep(200 * time.Millisecond)
		showInDock()
		invokeSync(func() {
			a.window.Show()
			a.window.Focus()
		})
		log.Printf("monban: IPC window shown, waiting for PIN")
	}

	// Wait for PIN from frontend or timeout/cancel
	select {
	case pin := <-a.ipc.pinCh:
		if pin == "" {
			writeIPCResponse(conn, monban.IPCResponse{Error: "cancelled by user"})
			return
		}
		err := a.performIPCAuth(pin)
		if err != nil {
			writeIPCResponse(conn, monban.IPCResponse{Error: err.Error()})
		} else {
			writeIPCResponse(conn, monban.IPCResponse{Success: true})
		}
		// Notify frontend of result
		a.ipc.resultCh <- err

	case <-ctx.Done():
		writeIPCResponse(conn, monban.IPCResponse{Error: "shutting down"})
	}
}

// performIPCAuth does a standalone FIDO2 assertion for the IPC auth request.
// This is independent of the app's own lock/unlock state.
func (a *App) performIPCAuth(pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if len(sc.Credentials) == 0 {
		return fmt.Errorf("no credentials registered")
	}

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
	}

	credIDs, err := sc.CollectCredentialIDs()
	if err != nil {
		return err
	}

	assertion, err := monban.Assert(pin, credIDs, hmacSalt)
	if err != nil {
		return fmt.Errorf("FIDO2 assertion failed: %w", err)
	}

	// Verify signature against stored public keys
	for i := range sc.Credentials {
		cred := &sc.Credentials[i]
		credID, _ := monban.DecodeB64(cred.CredentialID)
		if assertion.CredentialID != nil && !bytes.Equal(credID, assertion.CredentialID) {
			continue
		}
		if err := monban.VerifyAssertionWithSalt(sc.RpID, cred, hmacSalt, assertion.AuthDataCBOR, assertion.Sig); err == nil {
			return nil
		}
	}

	return fmt.Errorf("no matching registered key")
}

// GetPendingIPCAuth returns a snapshot of the current in-flight IPC auth
// request, or nil if none is active. Called by the frontend on mount to
// handle the cold-start case where the plugin connected before Events.On
// subscribed to ipc:auth-request.
func (a *App) GetPendingIPCAuth() *monban.IPCRequest {
	if a.ipc == nil {
		return nil
	}
	a.ipc.mu.Lock()
	defer a.ipc.mu.Unlock()
	if a.ipc.pending == nil {
		return nil
	}
	snapshot := *a.ipc.pending
	return &snapshot
}

// HandleIPCAuth is called by the frontend after the user enters their PIN.
func (a *App) HandleIPCAuth(pin string) error {
	if a.ipc == nil {
		return fmt.Errorf("IPC not active")
	}

	// Send PIN to the waiting socket handler
	select {
	case a.ipc.pinCh <- pin:
	default:
		return fmt.Errorf("no pending auth request")
	}

	// Wait for the result
	select {
	case err := <-a.ipc.resultCh:
		return err
	case <-time.After(ipcAuthTimeout):
		return fmt.Errorf("auth timed out")
	}
}

// HideToTray hides the window back to the system tray.
// If the app is locked with force auth, re-enters fullscreen instead.
func (a *App) HideToTray() {
	if a.window == nil {
		return
	}
	if a.IsLocked() && a.GetSettings().ForceAuthentication {
		a.EnterFullscreen()
		return
	}
	invokeSync(func() {
		a.window.Hide()
	})
	hideFromDock()
}

// CancelIPCAuth is called when the user dismisses the IPC auth dialog.
func (a *App) CancelIPCAuth() {
	if a.ipc == nil {
		return
	}
	select {
	case a.ipc.pinCh <- "":
	default:
	}
}

func writeIPCResponse(conn net.Conn, resp monban.IPCResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("monban: IPC marshal error: %v", err)
		return
	}
	if _, err := conn.Write(data); err != nil {
		log.Printf("monban: IPC write error: %v", err)
	}
}
