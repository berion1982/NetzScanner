package logintest

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
)

// parseSystemInfo wertet die Ausgabe von infoCommand aus (Kernel, Hostname, os-release).
func TestParseSystemInfo(t *testing.T) {
	raw := "#uname\nLinux 6.1.0 x86_64\n#host\nserver01\n#os\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\n"
	got := parseSystemInfo(raw)
	want := []Field{
		{"Kernel", "Linux 6.1.0 x86_64"},
		{"Hostname", "server01"},
		{"System", "Debian GNU/Linux 12 (bookworm)"},
		{"Version", "12"},
	}
	if len(got) != len(want) {
		t.Fatalf("erwartet %v, bekam %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Feld %d: erwartet %v, bekam %v", i, want[i], got[i])
		}
	}
}

// Fehlende Abschnitte (z. B. kein /etc/os-release) und Unsinn ergeben keine Fehler, nur weniger Felder.
func TestParseSystemInfoPartialAndGarbage(t *testing.T) {
	if got := parseSystemInfo("#uname\nFreeBSD 14.0 amd64\n#os\n"); len(got) != 1 || got[0].Name != "Kernel" {
		t.Fatalf("nur Kernel erwartet: %v", got)
	}
	if got := parseSystemInfo("% Unknown command\r\n"); len(got) != 0 {
		t.Fatalf("keine Felder erwartet: %v", got)
	}
}

// Werte vom Geraet werden von Steuerzeichen befreit und gekuerzt.
func TestCleanValue(t *testing.T) {
	if got := cleanValue("a\x1b[31mb\x00c"); strings.ContainsAny(got, "\x1b\x00") {
		t.Fatalf("Steuerzeichen nicht entfernt: %q", got)
	}
	if got := cleanValue(strings.Repeat("x", 500)); len([]rune(got)) > 121 {
		t.Fatalf("nicht gekuerzt: %d Zeichen", len([]rune(got)))
	}
}

// Auch ohne erlaubte Sitzung bleibt der Login "ok" (Info leer), und das Passwort wird genau einmal gesendet.
func TestSSHInfoSessionRefused(t *testing.T) {
	port, fp, tries := startSSH(t) // Testserver lehnt Sitzungen ab
	r := SSHInfo(context.Background(), "127.0.0.1", port, "admin", "geheim", fp)
	if r.Status != StatusOK || len(r.Info) != 0 {
		t.Fatalf("ok ohne Infos erwartet: %+v", r)
	}
	if n := atomic.LoadInt32(tries); n != 1 {
		t.Fatalf("genau 1 Passwortversuch erwartet, waren %d", n)
	}
}

// SSHInfo sendet ohne bestaetigten Hostkey ebenfalls KEIN Passwort.
func TestSSHInfoNeedsConfirm(t *testing.T) {
	port, _, tries := startSSH(t)
	r := SSHInfo(context.Background(), "127.0.0.1", port, "admin", "geheim", "")
	if r.Status != StatusConfirm || atomic.LoadInt32(tries) != 0 {
		t.Fatalf("confirm ohne Passwort erwartet: %+v", r)
	}
}
