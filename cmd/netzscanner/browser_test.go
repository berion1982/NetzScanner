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

// Port (I-088/I-089): Ohne --listen immer ein freier Port auf 127.0.0.1 (nie ein fester
// Standardport), mit ausdruecklichem --listen genau diese Adresse; lokal gibt es dann
// ein Token, mit --listen/--no-token oder offener Adresse nicht (dort gilt I-025).
func TestOpenListenerUndToken(t *testing.T) {
	a, err := openListener(false, "0.0.0.0:8484")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := openListener(false, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ta, tb := a.Addr().(*net.TCPAddr), b.Addr().(*net.TCPAddr)
	if !ta.IP.IsLoopback() || !tb.IP.IsLoopback() {
		t.Errorf("nur Loopback erwartet: %s, %s", ta, tb)
	}
	if ta.Port == tb.Port || ta.Port == 8484 && tb.Port == 8484 {
		t.Errorf("zwei Instanzen muessen verschiedene Ports bekommen: %d, %d", ta.Port, tb.Port)
	}
	if _, err := openListener(true, a.Addr().String()); err == nil {
		t.Error("mit ausdruecklichem --listen: genau diese Adresse, Fehler wenn belegt")
	}

	if !autoToken(false, false, "127.0.0.1:5000") {
		t.Error("Normalbetrieb lokal: Token erwartet")
	}
	if autoToken(true, false, "127.0.0.1:8484") || autoToken(false, true, "127.0.0.1:5000") || autoToken(false, false, "0.0.0.0:8484") {
		t.Error("kein automatisches Token bei --listen, --no-token oder offener Adresse")
	}
}
