package web

import (
	"strings"
	"testing"
	"time"
)

// Passwort wird gemerkt, aber die Listen-Sicht enthaelt es nie.
func TestCredStoreListHasNoPassword(t *testing.T) {
	cs := newCredStore(time.Minute)
	cs.set("192.168.1.5", "admin", "geheim123")
	for _, c := range cs.list() {
		if strings.Contains(c.User+c.IP, "geheim123") {
			t.Fatal("Passwort in der Liste")
		}
	}
	u, p, ok := cs.get("192.168.1.5")
	if !ok || u != "admin" || p != "geheim123" {
		t.Fatalf("get: %v %q %q", ok, u, p)
	}
}

// Nach der Inaktivitaetsfrist ist der Zugang weg; Nutzung verlaengert die Frist.
func TestCredStoreIdleTimeout(t *testing.T) {
	cs := newCredStore(10 * time.Minute)
	now := time.Now()
	cs.now = func() time.Time { return now }
	cs.set("10.0.0.1", "u", "p")
	now = now.Add(9 * time.Minute)
	if _, _, ok := cs.get("10.0.0.1"); !ok { // Nutzung setzt die Frist neu
		t.Fatal("zu frueh vergessen")
	}
	now = now.Add(9 * time.Minute)
	if len(cs.list()) != 1 {
		t.Fatal("Frist haette durch get verlaengert sein muessen")
	}
	now = now.Add(11 * time.Minute)
	if len(cs.list()) != 0 {
		t.Fatal("nicht vergessen")
	}
}

// remove("") loescht alle, remove(ip) nur einen.
func TestCredStoreRemove(t *testing.T) {
	cs := newCredStore(time.Minute)
	cs.set("1.1.1.1", "a", "x")
	cs.set("2.2.2.2", "b", "y")
	cs.remove("1.1.1.1")
	if len(cs.list()) != 1 {
		t.Fatal("Einzel-Loeschen")
	}
	cs.remove("")
	if len(cs.list()) != 0 {
		t.Fatal("Alle-Loeschen")
	}
}
