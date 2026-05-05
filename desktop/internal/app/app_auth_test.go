package app

import (
	"strings"
	"testing"

	"monban/internal/monban"
)

func TestLock_NilConfig(t *testing.T) {
	a := NewApp()
	a.secureCfg = nil

	err := a.Lock()
	if err == nil {
		t.Fatal("Lock() should fail with nil secureCfg")
	}
	if !strings.Contains(err.Error(), "config not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLock_NilConfig_PreservesSecrets(t *testing.T) {
	a := NewApp()
	a.masterSecret = monban.WrapMasterSecret(make([]byte, 64))
	a.encKey = make([]byte, 32)
	for i := range a.encKey {
		a.encKey[i] = 0x42
	}

	a.secureCfg = nil
	err := a.Lock()
	if err == nil {
		t.Fatal("Lock should fail with nil config")
	}

	// Lock returns early before zeroing when config is nil
	if a.masterSecret == nil {
		t.Error("masterSecret should be preserved on early error return")
	}
	if a.encKey == nil {
		t.Error("encKey should be preserved on early error return")
	}
}

func TestPrepareAdditionalKey_Locked(t *testing.T) {
	a := NewApp() // starts locked

	_, _, _, err := a.prepareAdditionalKey()
	if err == nil {
		t.Fatal("prepareAdditionalKey should fail when locked")
	}
	if !strings.Contains(err.Error(), "must be unlocked") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareAdditionalKey_NilMasterSecret(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.masterSecret = nil

	_, _, _, err := a.prepareAdditionalKey()
	if err == nil {
		t.Fatal("prepareAdditionalKey should fail with nil masterSecret")
	}
	if !strings.Contains(err.Error(), "must be unlocked") {
		t.Errorf("unexpected error: %v", err)
	}
}
