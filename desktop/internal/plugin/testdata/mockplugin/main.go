// mockplugin is a minimal plugin binary used by host_test.go to exercise
// the spawn, handshake, hook, and shutdown paths.
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
				Name:     "mock-plugin",
				Version:  "0.1.0",
				Hooks:    []string{"on:app_started"},
				Provides: []any{},
				Ready:    true,
			})
			out, _ := json.Marshal(message{ID: in.ID, Type: "response", Result: res})
			_, _ = w.Write(append(out, '\n'))
			_ = w.Flush()
		case "on:app_started":
			// Signal via stderr so the test can observe that the
			// fan-out actually reached us.
			fmt.Fprintln(os.Stderr, "MOCK_HOOK_RECEIVED on:app_started")
		case "shutdown":
			return
		}
	}
}
