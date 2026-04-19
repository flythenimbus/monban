package app

import (
	"strings"
	"testing"
)

func TestRemoveKey_Locked(t *testing.T) {
	a := NewApp() // starts locked

	err := a.RemoveKey("some-cred-id", "1234")
	if err == nil {
		t.Fatal("RemoveKey should fail when locked")
	}
	if !strings.Contains(err.Error(), "must be unlocked") {
		t.Errorf("unexpected error: %v", err)
	}
}
