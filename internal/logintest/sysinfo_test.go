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

// Erweiterte Infos (I-023 Rest): Modell, Firmware, Laufzeit und Schnittstellen aus "ip -o".
func TestParseSystemInfoExtended(t *testing.T) {
	raw := "#uname\nLinux 6.1.0 x86_64\n#owrt\nDISTRIB_DESCRIPTION='OpenWrt 23.05.0'\n" +
		"#model\nTestModell 1\n#bios\nF12\n#up\n90061.52 1000.0\n" +
		"#addr\n1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.0.2.5/24 brd 192.0.2.255 scope global eth0\n" +
		"#link\n1: lo: <LOOPBACK,UP> mtu 65536 state UNKNOWN mode DEFAULT link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n" +
		"2: eth0: <BROADCAST,UP> mtu 1500 state UP mode DEFAULT link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n"
	got := map[string]string{}
	for _, f := range parseSystemInfo(raw) {
		got[f.Name] = f.Value
	}
	want := map[string]string{
		"Firmware":           "OpenWrt 23.05.0",
		"Modell":             "TestModell 1",
		"BIOS/Firmware":      "F12",
		"Laufzeit":           "1 T 1 Std 1 Min",
		"Schnittstelle eth0": "UP · aa:bb:cc:dd:ee:ff · 192.0.2.5/24",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: erwartet %q, bekam %q", k, v, got[k])
		}
	}
	if _, ok := got["Schnittstelle lo"]; ok {
		t.Error("Loopback sollte entfallen")
	}
}
