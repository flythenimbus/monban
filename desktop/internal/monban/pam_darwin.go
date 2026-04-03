package monban

import (
	"fmt"
	"os"
	"os/exec"
)

func pamSudoPath() string {
	return "/etc/pam.d/sudo_local"
}

func pamSuPath() string {
	return "/etc/pam.d/su"
}

func secureConfigDir() string {
	return "/Library/Application Support/monban"
}

// RunWithPrivileges executes a shell command with root privileges using
// osascript to present a native macOS authorization dialog.
// The command is passed directly to `do shell script` which runs /bin/sh -c.
func RunWithPrivileges(shellCmd string) error {
	script := fmt.Sprintf(
		`do shell script %q with administrator privileges`,
		shellCmd,
	)

	cmd := exec.Command("osascript", "-e", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
