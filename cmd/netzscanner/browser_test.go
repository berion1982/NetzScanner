package main

import (
	"net"
	"testing"
)

// Browser nur bei lokalem Server und ohne --no-browser.
func TestShouldOpenBrowser(t *testing.T) {
	cases := []struct {
		noBrowser bool
		listen    string
		want      bool
	}{
		{false, "127.0.0.1:8484", true},
		{false, "localhost:8484", true},
		{false, "[::1]:8484", true},
		{true, "127.0.0.1:8484", false},
		{false, "0.0.0.0:8484", false},
		{false, ":8484", false},
	}
	for _, c := range cases {
		if got := shouldOpenBrowser(c.noBrowser, c.listen); got != c.want {
			t.Errorf("shouldOpenBrowser(%v,%q)=%v, erwartet %v", c.noBrowser, c.listen, got, c.want)
		}
	}
}

// Je Betriebssystem der passende Systembefehl mit der URL als letztem Argument.
func TestBrowserCommand(t *testing.T) {
	u := "http://127.0.0.1:8484"
	for goos, want := range map[string]string{"linux": "xdg-open", "windows": "rundll32", "darwin": "open"} {
		name, args := browserCommand(goos, u)
		if name != want || args[len(args)-1] != u {
			t.Errorf("%s: %s %v", goos, name, args)
		}
	}
}

// Port-Suche (I-088): Ohne --listen weicht der Server auf einen freien Port aus, mit
// ausdruecklichem --listen nicht; lokal gibt es dann ein Token, mit --listen/--no-token nicht.
func TestOpenListenerUndToken(t *testing.T) {
	// Belegt den Standardport (falls er frei ist), damit der Ausweichpfad geprueft wird.
	busy, err := net.Listen("tcp", defaultListen)
	if err != nil {
		t.Skip("Standardport 8484 ist auf diesem Rechner schon belegt")
	}
	defer busy.Close()

	ln, err := openListener(false, defaultListen)
	if err != nil {
		t.Fatalf("ohne --listen muss ein freier Port gefunden werden: %v", err)
	}
	defer ln.Close()
	if ln.Addr().String() == defaultListen {
		t.Errorf("Ausweichport erwartet, bekam %s", ln.Addr())
	}
	if _, err := openListener(true, defaultListen); err == nil {
		t.Error("mit ausdruecklichem --listen darf kein Ausweichen stattfinden")
	}

	if !autoToken(false, false, "127.0.0.1:5000") {
		t.Error("Normalbetrieb lokal: Token erwartet")
	}
	if autoToken(true, false, "127.0.0.1:8484") || autoToken(false, true, "127.0.0.1:5000") || autoToken(false, false, "0.0.0.0:8484") {
		t.Error("kein automatisches Token bei --listen, --no-token oder offener Adresse (dort gilt I-025)")
	}
}
