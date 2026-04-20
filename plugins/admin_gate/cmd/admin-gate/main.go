// admin-gate is the Monban plugin that gates sudo and macOS admin
// authorization dialogs behind a YubiKey FIDO2 assertion.
//
// P3b stage 1 (this build): scaffolding only. Responds to hello and
// shutdown so the plugin host is happy; the install_pkg sub-installer
// is what actually touches system state. Stage 2 wires up the PAM
// helper's IPC socket and the request_pin_touch flow.
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

type settings struct {
	StrictMode bool `json:"strict_mode"`
}

func main() {
	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	var cfg settings

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
			var hp struct {
				Config json.RawMessage `json:"config,omitempty"`
			}
			_ = json.Unmarshal(in.Params, &hp)
			applySettings(&cfg, hp.Config)
			res, _ := json.Marshal(helloResult{
				Name:     "admin-gate",
				Version:  "0.1.0",
				Hooks:    []string{"on:app_started", "on:app_shutdown"},
				Provides: []any{},
				Ready:    true,
			})
			_ = write(w, message{ID: in.ID, Type: "response", Result: res})
		case "on:app_started":
			logLine(w, "info", fmt.Sprintf("admin-gate online (strict_mode=%v)", cfg.StrictMode))
		case "on:app_shutdown":
			logLine(w, "info", "admin-gate offline")
		case "settings.apply":
			applySettings(&cfg, in.Params)
			logLine(w, "info", fmt.Sprintf("applied settings: strict_mode=%v", cfg.StrictMode))
			res, _ := json.Marshal(map[string]any{"ok": true})
			_ = write(w, message{ID: in.ID, Type: "response", Result: res})
		case "shutdown":
			return
		default:
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

func applySettings(cfg *settings, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var incoming map[string]json.RawMessage
	if err := json.Unmarshal(raw, &incoming); err != nil {
		return
	}
	if v, ok := incoming["strict_mode"]; ok {
		_ = json.Unmarshal(v, &cfg.StrictMode)
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
