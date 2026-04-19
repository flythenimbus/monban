package app

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"monban/internal/monban"
)

func TestHandleIPCAuth_NilIPC(t *testing.T) {
	a := NewApp()
	a.ipc = nil

	err := a.HandleIPCAuth("1234")
	if err == nil {
		t.Fatal("HandleIPCAuth should fail with nil ipc")
	}
	if !strings.Contains(err.Error(), "IPC not active") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHandleIPCAuth_NoPendingRequest(t *testing.T) {
	a := NewApp()
	a.ipc = &ipcState{
		pinCh:    make(chan string, 1),
		resultCh: make(chan error, 1),
	}

	// Fill the pinCh so the next send would block (simulating no listener)
	a.ipc.pinCh <- "blocked"

	err := a.HandleIPCAuth("1234")
	if err == nil {
		t.Fatal("HandleIPCAuth should fail when no goroutine is reading pinCh")
	}
	if !strings.Contains(err.Error(), "no pending auth request") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCancelIPCAuth_NilIPC(t *testing.T) {
	a := NewApp()
	a.ipc = nil

	// Should not panic
	a.CancelIPCAuth()
}

func TestCancelIPCAuth_NoPendingRequest(t *testing.T) {
	a := NewApp()
	a.ipc = &ipcState{
		pinCh:    make(chan string, 1),
		resultCh: make(chan error, 1),
	}
	// Fill pinCh
	a.ipc.pinCh <- "blocked"

	// Should not panic — default case swallows it
	a.CancelIPCAuth()
}

func TestCancelIPCAuth_SendsEmptyPin(t *testing.T) {
	a := NewApp()
	a.ipc = &ipcState{
		pinCh:    make(chan string, 1),
		resultCh: make(chan error, 1),
	}

	a.CancelIPCAuth()

	select {
	case pin := <-a.ipc.pinCh:
		if pin != "" {
			t.Errorf("CancelIPCAuth should send empty string, got %q", pin)
		}
	default:
		t.Error("CancelIPCAuth should have sent a value on pinCh")
	}
}

func TestStopIPCListener_NilIPC(t *testing.T) {
	a := NewApp()
	a.ipc = nil

	// Should not panic
	a.StopIPCListener()
}

func TestWriteIPCResponse_Success(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	go writeIPCResponse(server, monban.IPCResponse{Success: true})

	var resp monban.IPCResponse
	decoder := json.NewDecoder(client)
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected Success=true")
	}
	if resp.Error != "" {
		t.Errorf("expected no error, got %q", resp.Error)
	}
}

func TestWriteIPCResponse_Error(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	go writeIPCResponse(server, monban.IPCResponse{Error: "test error"})

	var resp monban.IPCResponse
	decoder := json.NewDecoder(client)
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Error("expected Success=false")
	}
	if resp.Error != "test error" {
		t.Errorf("error = %q, want %q", resp.Error, "test error")
	}
}

func TestWriteIPCResponse_ClosedConn(t *testing.T) {
	server, client := net.Pipe()
	_ = client.Close() // close the read end

	// Should not panic on write error
	writeIPCResponse(server, monban.IPCResponse{Success: true})
	_ = server.Close()
}

func TestHideToTray_NilWindow(t *testing.T) {
	stubHooks(t)
	a := NewApp()
	// Should not panic with nil window
	a.HideToTray()
}
