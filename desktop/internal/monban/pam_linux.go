package monban

import (
	"os"
	"os/exec"
)

// RunWithPrivileges executes a shell command with root privileges using pkexec.
func RunWithPrivileges(shellCmd string) error {
	cmd := exec.Command("pkexec", "sh", "-c", shellCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func pamSudoPath() string {
	return "/etc/pam.d/sudo"
}

func pamSuPath() string {
	return "/etc/pam.d/su"
}
