package plugin

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	c := NewCodec(&buf, &buf)

	in := &Message{ID: "42", Type: TypeRequest, Method: "hello", Params: json.RawMessage(`{"x":1}`)}
	if err := c.Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out, err := c.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.ID != in.ID || out.Method != in.Method || out.Type != in.Type {
		t.Errorf("roundtrip mismatch: got %+v", out)
	}
	if string(out.Params) != `{"x":1}` {
		t.Errorf("params = %s", out.Params)
	}
}

func TestCodecReadEOF(t *testing.T) {
	c := NewCodec(&bytes.Buffer{}, &bytes.Buffer{})
	if _, err := c.Read(); err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestCodecReadTruncated(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"type":"notify"`) // no trailing brace, no newline
	c := NewCodec(&buf, &bytes.Buffer{})
	if _, err := c.Read(); err == nil {
		t.Error("expected error on truncated frame")
	}
}

func TestCodecConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	c := NewCodec(&bytes.Buffer{}, &buf)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = c.Write(&Message{Type: TypeNotify, Method: "log", Params: json.RawMessage(`{"n":1}`)})
		}(i)
	}
	wg.Wait()

	// Every line must be a parseable frame. No interleaving = each line
	// decodes cleanly.
	r := NewCodec(&buf, &bytes.Buffer{})
	seen := 0
	for {
		m, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("parse frame %d: %v", seen, err)
		}
		if m.Method != "log" {
			t.Errorf("frame %d: method = %q", seen, m.Method)
		}
		seen++
	}
	if seen != 20 {
		t.Errorf("expected 20 frames, got %d", seen)
	}
}

func TestRPCErrorString(t *testing.T) {
	e := &RPCError{Code: -32601, Message: "not found"}
	if s := e.Error(); s == "" {
		t.Error("Error() should not be empty")
	}
}
