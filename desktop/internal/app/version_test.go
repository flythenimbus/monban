package app

import "testing"

func TestVersionDefault(t *testing.T) {
	// Version is set to "dev" by default, overridden at build time via ldflags.
	if Version != "dev" {
		t.Errorf("default Version = %q, want %q", Version, "dev")
	}
}
