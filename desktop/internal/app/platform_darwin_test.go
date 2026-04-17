//go:build darwin

package app

import (
	"testing"

	"github.com/wailsapp/wails/v3/pkg/application"
)

func TestPlatformAppOptions(t *testing.T) {
	opts := PlatformAppOptions()
	if opts.ActivationPolicy != application.ActivationPolicyAccessory {
		t.Errorf("ActivationPolicy = %v, want ActivationPolicyAccessory", opts.ActivationPolicy)
	}
}

func TestPlatformWindowOptions(t *testing.T) {
	opts := PlatformWindowOptions()
	if opts.InvisibleTitleBarHeight != 50 {
		t.Errorf("InvisibleTitleBarHeight = %d, want 50", opts.InvisibleTitleBarHeight)
	}
	if opts.Backdrop != application.MacBackdropTranslucent {
		t.Errorf("Backdrop = %v, want MacBackdropTranslucent", opts.Backdrop)
	}
	if opts.TitleBar != application.MacTitleBarHiddenInset {
		t.Errorf("TitleBar = %v, want MacTitleBarHiddenInset", opts.TitleBar)
	}
}
