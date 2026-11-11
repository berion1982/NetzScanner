//go:build windows

package scan

import (
	"os/exec"
	"syscall"
)

// createNoWindow ist das Windows-Flag CREATE_NO_WINDOW: Der Kindprozess bekommt
// kein eigenes Konsolenfenster.
const createNoWindow = 0x08000000

// hidden verhindert, dass beim Aufruf von Systembefehlen (ping, arp, route,
// powershell ...) kurz ein Konsolenfenster aufblitzt. Das passiert sonst, wenn
// NetzScanner selbst ohne Konsole laeuft (Windows-Build mit -H=windowsgui, I-083).
func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}
