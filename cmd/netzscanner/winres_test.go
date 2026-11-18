package main

import (
	"debug/pe"
	"testing"
)

// Die eingecheckten Ressourcendateien (Programm-Icon der Windows-.exe, I-086) muessen
// lesbar sein und einen nicht-leeren ".rsrc"-Abschnitt enthalten. Neu erzeugen mit
// scripts/make-winres.sh.
func TestWindowsIconRessourcen(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		f, err := pe.Open("rsrc_windows_" + arch + ".syso")
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		sec := f.Section(".rsrc")
		if sec == nil || sec.Size == 0 {
			t.Errorf("%s: kein .rsrc-Abschnitt", arch)
		}
		f.Close()
	}
}
