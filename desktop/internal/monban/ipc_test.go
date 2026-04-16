package monban

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIPCSocketPath(t *testing.T) {
	dir := t.TempDir()
	origDir := ConfigDir
	ConfigDir = func() string { return dir }
	defer func() { ConfigDir = origDir }()

	got := IPCSocketPath()
	want := filepath.Join(dir, "monban.sock")
	if got != want {
		t.Errorf("IPCSocketPath() = %q, want %q", got, want)
	}
}

func TestCleanStaleSocketRemovesSocket(t *testing.T) {
	dir := t.TempDir()
	origDir := ConfigDir
	ConfigDir = func() string { return dir }
	defer func() { ConfigDir = origDir }()

	sockPath := IPCSocketPath()
	if err := os.WriteFile(sockPath, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	CleanStaleSocket()

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Error("CleanStaleSocket should remove the socket file")
	}
}

func TestCleanStaleSocketNoOpWhenMissing(t *testing.T) {
	dir := t.TempDir()
	origDir := ConfigDir
	ConfigDir = func() string { return dir }
	defer func() { ConfigDir = origDir }()

	// Should not panic or error when socket doesn't exist.
	CleanStaleSocket()
}

func TestCleanStaleSocketWorksWhileDirLocked(t *testing.T) {
	dir := t.TempDir()
	origDir := ConfigDir
	ConfigDir = func() string { return dir }
	defer func() {
		UnlockConfigDir()
		ConfigDir = origDir
	}()

	sockPath := IPCSocketPath()
	if err := os.WriteFile(sockPath, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	LockConfigDir()
	CleanStaleSocket()

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Error("CleanStaleSocket should remove socket even when dir is locked")
	}

	// Dir should be re-locked after cleanup.
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, []byte("x"), 0600); err == nil {
		t.Error("directory should be re-locked after CleanStaleSocket")
	}
}

func TestIPCRequestResponseRoundTrip(t *testing.T) {
	req := IPCRequest{
		Type:    "auth",
		User:    "testuser",
		Service: "authorization",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	var decoded IPCRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Type != req.Type {
		t.Errorf("Type: got %q, want %q", decoded.Type, req.Type)
	}
	if decoded.User != req.User {
		t.Errorf("User: got %q, want %q", decoded.User, req.User)
	}
	if decoded.Service != req.Service {
		t.Errorf("Service: got %q, want %q", decoded.Service, req.Service)
	}
}

func TestIPCResponseSuccess(t *testing.T) {
	resp := IPCResponse{Success: true}
	data, _ := json.Marshal(resp)

	var decoded IPCResponse
	_ = json.Unmarshal(data, &decoded)

	if !decoded.Success {
		t.Error("Success should be true")
	}
	if decoded.Error != "" {
		t.Errorf("Error should be empty, got %q", decoded.Error)
	}
}

func TestIPCResponseError(t *testing.T) {
	resp := IPCResponse{Error: "auth failed"}
	data, _ := json.Marshal(resp)

	var decoded IPCResponse
	_ = json.Unmarshal(data, &decoded)

	if decoded.Success {
		t.Error("Success should be false")
	}
	if decoded.Error != "auth failed" {
		t.Errorf("Error: got %q, want %q", decoded.Error, "auth failed")
	}
}

func TestIPCResponseErrorOmittedWhenEmpty(t *testing.T) {
	resp := IPCResponse{Success: true}
	data, _ := json.Marshal(resp)

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)

	if _, exists := raw["error"]; exists {
		t.Error("error field should be omitted when empty")
	}
}

// TestIPCProtocolOverSocket verifies JSON request/response over a real Unix socket.
func TestIPCProtocolOverSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Server goroutine: read request, write response.
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var req IPCRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			t.Errorf("server decode: %v", err)
			return
		}
		if req.Type != "auth" || req.User != "alice" || req.Service != "sudo" {
			t.Errorf("unexpected request: %+v", req)
		}

		resp := IPCResponse{Success: true}
		data, _ := json.Marshal(resp)
		conn.Write(data)
	}()

	// Client: connect, send request, read response.
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := IPCRequest{Type: "auth", User: "alice", Service: "sudo"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}

	var resp IPCResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if !resp.Success {
		t.Error("expected success response")
	}

	<-done
}

// TestIPCProtocolOverSocketDenied verifies a denied auth response.
func TestIPCProtocolOverSocketDenied(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var req IPCRequest
		json.NewDecoder(conn).Decode(&req)

		resp := IPCResponse{Error: "cancelled by user"}
		data, _ := json.Marshal(resp)
		conn.Write(data)
	}()

	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := IPCRequest{Type: "auth", User: "bob", Service: "authorization"}
	json.NewEncoder(conn).Encode(req)

	var resp IPCResponse
	json.NewDecoder(conn).Decode(&resp)

	if resp.Success {
		t.Error("expected denied response")
	}
	if resp.Error != "cancelled by user" {
		t.Errorf("Error: got %q, want %q", resp.Error, "cancelled by user")
	}
}

// TestIPCConcurrentConnectionsRejected verifies only one auth at a time.
func TestIPCConcurrentConnectionsRejected(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Simulate a server that holds the first connection busy.
	var activeConn net.Conn
	ready := make(chan struct{})

	go func() {
		conn1, _ := listener.Accept()
		activeConn = conn1
		close(ready)

		// Accept second connection and immediately reject.
		conn2, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn2.Close()

		var req IPCRequest
		json.NewDecoder(conn2).Decode(&req)

		resp := IPCResponse{Error: "another auth request is in progress"}
		data, _ := json.Marshal(resp)
		conn2.Write(data)
	}()

	// First client connects (held busy).
	conn1, _ := net.DialTimeout("unix", sockPath, 2*time.Second)
	defer func() {
		if conn1 != nil {
			conn1.Close()
		}
		if activeConn != nil {
			activeConn.Close()
		}
	}()
	<-ready

	// Second client connects while first is active.
	conn2, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	req := IPCRequest{Type: "auth", User: "eve", Service: "sudo"}
	json.NewEncoder(conn2).Encode(req)

	var resp IPCResponse
	json.NewDecoder(conn2).Decode(&resp)

	if resp.Success {
		t.Error("second connection should be rejected")
	}
	if resp.Error != "another auth request is in progress" {
		t.Errorf("Error: got %q", resp.Error)
	}
}
