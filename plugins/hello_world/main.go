// hello-world is the reference / smoke-test plugin for the Monban plugin
// host. It implements the minimum hello handshake, stores its config on
// hello + settings.apply, and uses greeting/verbose when logging lifecycle
// notifies.
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

type helloParams struct {
	HostVersion string          `json:"host_version"`
	HostAPI     string          `json:"host_api"`
	Config      json.RawMessage `json:"config,omitempty"`
}

type helloResult struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Hooks    []string `json:"hooks"`
	Provides []any    `json:"provides"`
	Ready    bool     `json:"ready"`
}

type settings struct {
	Verbose  bool   `json:"verbose"`
	Greeting string `json:"greeting"`
}

func main() {
	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	cfg := settings{Greeting: "hello"} // manifest default

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
			var hp helloParams
			_ = json.Unmarshal(in.Params, &hp)
			applySettings(&cfg, hp.Config)
			res, _ := json.Marshal(helloResult{
				Name:     "hello-world",
				Version:  "0.1.0",
				Hooks:    []string{"on:app_started", "on:app_shutdown", "on:settings_changed"},
				Provides: []any{},
				Ready:    true,
			})
			_ = write(w, message{ID: in.ID, Type: "response", Result: res})
		case "on:app_started":
			logLine(w, "info", fmt.Sprintf("monban started — %s from hello-world", cfg.Greeting))
			if cfg.Verbose {
				logLine(w, "info", "verbose on")
			}
		case "on:app_shutdown":
			logLine(w, "info", fmt.Sprintf("monban shutting down — %s, hello-world exiting", cfg.Greeting))
		case "on:settings_changed":
			if cfg.Verbose {
				logLine(w, "info", "settings changed")
			}
		case "settings.apply":
			applySettings(&cfg, in.Params)
			logLine(w, "info", fmt.Sprintf("applied settings: greeting=%q verbose=%v", cfg.Greeting, cfg.Verbose))
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

// applySettings merges a raw JSON blob into cfg. Missing or malformed
// fields leave the current value untouched.
func applySettings(cfg *settings, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var incoming map[string]json.RawMessage
	if err := json.Unmarshal(raw, &incoming); err != nil {
		return
	}
	if v, ok := incoming["verbose"]; ok {
		_ = json.Unmarshal(v, &cfg.Verbose)
	}
	if v, ok := incoming["greeting"]; ok {
		_ = json.Unmarshal(v, &cfg.Greeting)
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
