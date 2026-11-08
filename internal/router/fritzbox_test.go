package router

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeBox spielt eine FRITZ!Box nach: Digest-Anmeldung (MD5, qop=auth) und Hosts:1.
// Zaehlt die Anmeldeversuche mit falschem Passwort.
type fakeBox struct {
	user, pass string
	failures   int
	entries    []string // Rohwerte: ip|mac|name|iface|active
}

func md5hex(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }

func (f *fakeBox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const realm, nonce = "F!Box SOAP-Auth", "abc123"
	auth := r.Header.Get("Authorization")
	ok := false
	if strings.HasPrefix(auth, "Digest ") {
		p := map[string]string{}
		for _, kv := range splitParams(auth[7:]) {
			k, v, _ := strings.Cut(kv, "=")
			p[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
		ha1 := md5hex(f.user + ":" + realm + ":" + f.pass)
		ha2 := md5hex("POST:" + p["uri"])
		want := md5hex(ha1 + ":" + nonce + ":" + p["nc"] + ":" + p["cnonce"] + ":auth:" + ha2)
		ok = p["username"] == f.user && p["response"] == want
		if !ok {
			f.failures++
		}
	}
	if !ok {
		w.Header().Set("WWW-Authenticate", `Digest realm="`+realm+`", nonce="`+nonce+`", algorithm=MD5, qop="auth"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	act := r.Header.Get("SoapAction")
	switch {
	case strings.HasSuffix(act, "#GetHostNumberOfEntries"):
		fmt.Fprintf(w, `<s:Envelope xmlns:s="x"><s:Body><u:GetHostNumberOfEntriesResponse xmlns:u="y"><NewHostNumberOfEntries>%d</NewHostNumberOfEntries></u:GetHostNumberOfEntriesResponse></s:Body></s:Envelope>`, len(f.entries))
	case strings.HasSuffix(act, "#GetGenericHostEntry"):
		var buf [4096]byte
		n, _ := r.Body.Read(buf[:])
		var idx int
		fmt.Sscanf(string(buf[:n])[strings.Index(string(buf[:n]), "<NewIndex>")+len("<NewIndex>"):], "%d", &idx)
		e := strings.Split(f.entries[idx], "|")
		fmt.Fprintf(w, `<s:Envelope xmlns:s="x"><s:Body><u:GetGenericHostEntryResponse xmlns:u="y"><NewIPAddress>%s</NewIPAddress><NewMACAddress>%s</NewMACAddress><NewAddressSource>DHCP</NewAddressSource><NewInterfaceType>%s</NewInterfaceType><NewActive>%s</NewActive><NewHostName>%s</NewHostName></u:GetGenericHostEntryResponse></s:Body></s:Envelope>`, e[0], e[1], e[3], e[4], e[2])
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// Hilfsfunktion: startet den Fake auf 127.0.0.1:<Zufallsport> und biegt den Port um.
func withFake(t *testing.T, f *fakeBox) (host string, done func()) {
	t.Helper()
	srv := httptest.NewServer(f)
	u := strings.TrimPrefix(srv.URL, "http://")
	h, p, _ := net.SplitHostPort(u)
	old := tr064PortOverride
	tr064PortOverride = p
	return h, func() { tr064PortOverride = old; srv.Close() }
}

func TestReadFritzbox(t *testing.T) {
	f := &fakeBox{user: "u-4711", pass: "pw-geheim", entries: []string{
		"192.168.178.10|AA:BB:CC:00:11:22|homeassistant|Ethernet|1",
		"192.168.178.20|AA:BB:CC:00:11:33|Saschas-Handy|802.11|0",
	}}
	host, done := withFake(t, f)
	defer done()
	hosts, err := ReadFritzbox(context.Background(), host, "u-4711", "pw-geheim")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0].Name != "homeassistant" || hosts[0].Iface != "LAN (Kabel)" || !hosts[0].Active ||
		hosts[1].Iface != "WLAN" || hosts[1].Active {
		t.Errorf("Ergebnis: %+v", hosts)
	}
}

// Falsches Passwort: genau EIN abgelehnter Versuch, Fehlertext ohne Zugangsdaten.
func TestReadFritzboxWrongPassword(t *testing.T) {
	f := &fakeBox{user: "u-4711", pass: "pw-geheim"}
	host, done := withFake(t, f)
	defer done()
	_, err := ReadFritzbox(context.Background(), host, "u-4711", "pw-falsch")
	if err != ErrAuth {
		t.Fatalf("erwartet ErrAuth, bekam %v", err)
	}
	if f.failures != 1 {
		t.Errorf("Fehlversuche: %d, erwartet genau 1", f.failures)
	}
	if strings.Contains(err.Error(), "pw-falsch") || strings.Contains(err.Error(), "u-4711") {
		t.Error("Fehlertext enthaelt Zugangsdaten")
	}
}

func TestReadFritzboxBadHost(t *testing.T) {
	if _, err := ReadFritzbox(context.Background(), "fritz.box", "a", "b"); err == nil {
		t.Error("Hostname statt IP muss abgelehnt werden")
	}
}
