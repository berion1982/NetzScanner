package main

import "testing"

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
