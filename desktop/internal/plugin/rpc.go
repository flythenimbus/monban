package plugin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Message is the unified shape of every host ↔ plugin frame. The Type field
// disambiguates request/response/notify/error; unused fields are omitted.
type Message struct {
	ID     string          `json:"id,omitempty"`
	Type   string          `json:"type"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

const (
	TypeRequest  = "request"
	TypeResponse = "response"
	TypeNotify   = "notify"
	TypeError    = "error"
)

// RPCError is the error payload embedded in an error-type message.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// Codec is a newline-delimited JSON transport over a read/write pair.
// Safe for concurrent use: writes are serialized via a mutex; reads are
// intended to be driven by a single goroutine.
type Codec struct {
	r      *bufio.Reader
	w      io.Writer
	writeM sync.Mutex
}

// NewCodec wraps the given reader/writer pair. A buffered reader is created
// around r so callers shouldn't double-buffer.
func NewCodec(r io.Reader, w io.Writer) *Codec {
	return &Codec{r: bufio.NewReader(r), w: w}
}

// Read blocks until a full newline-delimited JSON message is available or
// the underlying reader returns an error. Returns io.EOF on clean close.
func (c *Codec) Read() (*Message, error) {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		if err == io.EOF && len(line) == 0 {
			return nil, io.EOF
		}
		if len(line) == 0 {
			return nil, err
		}
	}
	var m Message
	if jsonErr := json.Unmarshal(line, &m); jsonErr != nil {
		return nil, fmt.Errorf("decode rpc frame: %w", jsonErr)
	}
	return &m, nil
}

// Write serializes m and appends a trailing newline atomically.
func (c *Codec) Write(m *Message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode rpc frame: %w", err)
	}
	c.writeM.Lock()
	defer c.writeM.Unlock()
	if _, err := c.w.Write(data); err != nil {
		return err
	}
	if _, err := c.w.Write([]byte{'\n'}); err != nil {
		return err
	}
	return nil
}
