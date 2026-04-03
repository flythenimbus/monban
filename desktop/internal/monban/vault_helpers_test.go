package monban

import "testing"

func TestFindVaultIndex(t *testing.T) {
	vaults := []VaultEntry{
		{Label: "Docs", Path: "/home/user/Documents"},
		{Label: "Keys", Path: "/home/user/.ssh"},
		{Label: "secret.txt", Path: "/home/user/secret.txt", Type: "file"},
	}

	tests := []struct {
		path string
		want int
	}{
		{"/home/user/Documents", 0},
		{"/home/user/.ssh", 1},
		{"/home/user/secret.txt", 2},
		{"/nonexistent", -1},
		{"", -1},
	}

	for _, tt := range tests {
		got := FindVaultIndex(vaults, tt.path)
		if got != tt.want {
			t.Errorf("FindVaultIndex(%q) = %d, want %d", tt.path, got, tt.want)
		}
	}
}

func TestFindVaultIndexEmpty(t *testing.T) {
	got := FindVaultIndex(nil, "/some/path")
	if got != -1 {
		t.Errorf("FindVaultIndex on nil slice = %d, want -1", got)
	}
}
