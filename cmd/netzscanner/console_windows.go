//go:build windows

// Windows-Konsole (I-083 Teil 2): Die .exe wird als GUI-Programm gebaut
// (-H=windowsgui), damit beim Doppelklick kein Konsolenfenster aufgeht.
// Wird sie dagegen aus cmd/PowerShell gestartet (z. B. --version, --scan),
// haengen wir uns an deren Konsole an, damit die Ausgabe sichtbar bleibt.
package main

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	user32        = syscall.NewLazyDLL("user32.dll")
	attachConsole = kernel32.NewProc("AttachConsole")
	messageBoxW   = user32.NewProc("MessageBoxW")
)

// attachParentConsole haengt das Programm an die Konsole des startenden
// Programms an (ATTACH_PARENT_PROCESS = -1) und verbindet stdin/stdout/stderr
// neu. Ohne Eltern-Konsole (Doppelklick) schlaegt der Aufruf fehl: dann bleibt
// das Programm ohne Konsole. Rueckgabe: true, wenn eine Konsole vorhanden ist.
func attachParentConsole() bool {
	r, _, _ := attachConsole.Call(^uintptr(0)) // -1 = ATTACH_PARENT_PROCESS
	if r == 0 {
		return false
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
	return true
}

// showError zeigt eine Fehlermeldung als Windows-Meldungsfenster, weil ohne
// Konsole sonst niemand sie sehen wuerde (z. B. "Port belegt").
func showError(msg string) {
	t, _ := syscall.UTF16PtrFromString(msg)
	c, _ := syscall.UTF16PtrFromString("NetzScanner")
	const mbOK, mbIconError = 0x0, 0x10
	messageBoxW.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), mbOK|mbIconError)
}
