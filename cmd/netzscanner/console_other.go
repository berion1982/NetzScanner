//go:build !windows

package main

// Ausserhalb von Windows gibt es kein Konsolenproblem (siehe console_windows.go).

// attachParentConsole tut nichts; das Terminal ist ohnehin vorhanden.
func attachParentConsole() bool { return true }

// showError tut nichts; Fehler stehen im Terminal.
func showError(string) {}
