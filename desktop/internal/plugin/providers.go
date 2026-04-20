package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// AuthGateInput is the payload the host sends to every auth_gate
// provider during an unlock attempt. Mirrors the shape declared in
// docs/plugin-system.md.
type AuthGateInput struct {
	User    string   `json:"user"`
	Vaults  []string `json:"vaults,omitempty"`
	Attempt int      `json:"attempt"`
}

// AuthGateDecision is what a plugin returns from provide:auth_gate.
type AuthGateDecision struct {
	Decision  string `json:"decision"` // "allow" | "deny"
	Reason    string `json:"reason,omitempty"`
	UIMessage string `json:"ui_message,omitempty"`
}

// AuthGateResult is RunAuthGate's aggregate verdict. Plugin is the
// name of the plugin that produced the final decision (empty when
// the whole chain allowed, since no specific plugin "owns" the
// unanimous allow).
type AuthGateResult struct {
	Decision  string
	Reason    string
	UIMessage string
	Plugin    string
}

// DefaultAuthGateTimeout is used when a provider doesn't declare
// timeout_seconds in its manifest.
const DefaultAuthGateTimeout = 60 * time.Second

// RunAuthGate invokes provide:auth_gate on every loaded plugin whose
// manifest declares it, in priority order (lower number first; ties
// broken alphabetically). First deny wins and short-circuits the chain.
//
// Failure modes all collapse to deny: a plugin that times out, crashes,
// returns malformed JSON, or reports an unknown decision stops the
// unlock — fail closed is the only safe default because an auth-chain
// plugin exists precisely to add a gate, not to be skipped when broken.
// The lockout recovery path (CLI --disable-plugins) is the escape.
func (h *Host) RunAuthGate(ctx context.Context, in AuthGateInput) AuthGateResult {
	type target struct {
		plugin *Plugin
		spec   ProvideSpec
	}

	h.mu.Lock()
	var targets []target
	for _, p := range h.plugins {
		for _, pr := range p.Manifest.Provides {
			if pr.Name == "auth.gate" {
				targets = append(targets, target{p, pr})
				break
			}
		}
	}
	h.mu.Unlock()

	if len(targets) == 0 {
		return AuthGateResult{Decision: "allow"}
	}

	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].spec.Priority != targets[j].spec.Priority {
			return targets[i].spec.Priority < targets[j].spec.Priority
		}
		return targets[i].plugin.Manifest.Name < targets[j].plugin.Manifest.Name
	})

	params, err := json.Marshal(in)
	if err != nil {
		// Can't happen for our types, but refuse rather than silently
		// bypass the chain.
		return AuthGateResult{
			Decision: "deny",
			Reason:   fmt.Sprintf("marshal auth_gate input: %v", err),
		}
	}

	for _, t := range targets {
		timeout := time.Duration(t.spec.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = DefaultAuthGateTimeout
		}
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		h.log.Printf("plugin: invoking auth_gate %s (priority=%d, timeout=%s)",
			t.plugin.Manifest.Name, t.spec.Priority, timeout)
		msg, err := t.plugin.request(callCtx, "provide:auth_gate", params)
		cancel()

		if err != nil {
			return AuthGateResult{
				Decision: "deny",
				Reason:   fmt.Sprintf("plugin %q: %v", t.plugin.Manifest.Name, err),
				Plugin:   t.plugin.Manifest.Name,
			}
		}
		var d AuthGateDecision
		if uerr := json.Unmarshal(msg.Result, &d); uerr != nil {
			return AuthGateResult{
				Decision: "deny",
				Reason:   fmt.Sprintf("plugin %q returned invalid response: %v", t.plugin.Manifest.Name, uerr),
				Plugin:   t.plugin.Manifest.Name,
			}
		}
		if d.Decision != "allow" {
			return AuthGateResult{
				Decision:  "deny",
				Reason:    d.Reason,
				UIMessage: d.UIMessage,
				Plugin:    t.plugin.Manifest.Name,
			}
		}
	}

	return AuthGateResult{Decision: "allow"}
}
