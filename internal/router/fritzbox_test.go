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
	forbidden  bool     // true, sobald eine verbotene Aktion (Schluessel lesen / Setzen) aufgerufen wurde
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
	if strings.Contains(act, "SecurityKeys") || strings.Contains(act, "#Set") || strings.Contains(act, "#Add") || strings.Contains(act, "#Delete") {
		f.forbidden = true
	}
	// Weitere Dienste (I-055): Router-Info und WLAN. wlanconfig3 und PPP fehlen -> 404.
	resp := func(action string, fields map[string]string) {
		var b strings.Builder
		for k, v := range fields {
			fmt.Fprintf(&b, "<%s>%s</%s>", k, v, k)
		}
		fmt.Fprintf(w, `<s:Envelope xmlns:s="x"><s:Body><u:%sResponse xmlns:u="y">%s</u:%sResponse></s:Body></s:Envelope>`, action, b.String(), action)
	}
	switch {
	case r.URL.Path == "/upnp/control/deviceinfo":
		resp("GetInfo", map[string]string{"NewModelName": "FRITZ!Box 7590", "NewSoftwareVersion": "7.57", "NewUpTime": "90061"})
		return
	case r.URL.Path == "/upnp/control/wanipconnection1":
		resp("GetInfo", map[string]string{"NewConnectionStatus": "Connected", "NewUptime": "3600", "NewExternalIPAddress": "203.0.113.5"})
		return
	case r.URL.Path == "/upnp/control/wancommonifconfig1":
		resp("GetCommonLinkProperties", map[string]string{"NewWANAccessType": "DSL", "NewLayer1DownstreamMaxBitRate": "100000000", "NewLayer1UpstreamMaxBitRate": "40000000"})
		return
	case r.URL.Path == "/upnp/control/lanhostconfigmgm":
		resp("GetInfo", map[string]string{"NewDHCPServerEnable": "1", "NewMinAddress": "192.168.178.20", "NewMaxAddress": "192.168.178.200", "NewIPRouters": "192.168.178.1", "NewDNSServers": "192.168.178.1"})
		return
	case r.URL.Path == "/upnp/control/wlanconfig1" || r.URL.Path == "/upnp/control/wlanconfig2":
		n := strings.TrimPrefix(r.URL.Path, "/upnp/control/wlanconfig")
		switch {
		case strings.HasSuffix(act, "#GetInfo"):
			ch, ssid, beacon := "6", "Heimnetz", "11i"
			if n == "2" {
				ch, ssid, beacon = "36", "Gast", "None"
			}
			resp("GetInfo", map[string]string{"NewEnable": "1", "NewSSID": ssid, "NewChannel": ch, "NewStandard": "ax", "NewBeaconType": beacon})
		case strings.HasSuffix(act, "#GetTotalAssociations"):
			c := "0"
			if n == "1" {
				c = "1"
			}
			resp("GetTotalAssociations", map[string]string{"NewTotalAssociations": c})
		case strings.HasSuffix(act, "#GetGenericAssociatedDeviceInfo"):
			resp("GetGenericAssociatedDeviceInfo", map[string]string{"NewAssociatedDeviceMACAddress": "AA:BB:CC:00:11:33", "NewAssociatedDeviceIPAddress": "192.168.178.20", "NewX_AVM-DE_SignalStrength": "80", "NewX_AVM-DE_Speed": "866"})
		}
		return
	case strings.HasPrefix(r.URL.Path, "/upnp/control/wlanconfig") || r.URL.Path == "/upnp/control/wanpppconn1":
		w.WriteHeader(http.StatusNotFound)
		return
	}
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
	res, err := ReadFritzbox(context.Background(), host, "u-4711", "pw-geheim")
	if err != nil {
		t.Fatal(err)
	}
	hosts, info := res.Hosts, res.Info
	if f.forbidden {
		t.Error("verbotene Aktion aufgerufen (WLAN-Schluessel lesen oder Einstellung aendern)")
	}
	if info.Model != "FRITZ!Box 7590" || info.Firmware != "7.57" || info.WANStatus != "Connected" || info.DownKbps != 100000 ||
		!info.DHCPEnabled || info.DHCPFrom != "192.168.178.20" || len(info.WLANs) != 2 {
		t.Errorf("Info: %+v", info)
	}
	if w := info.WLANs[0]; w.SSID != "Heimnetz" || w.Band != "2,4 GHz" || w.Encryption != "WPA2" || w.Open || len(w.Clients) != 1 || w.Clients[0].Signal != 80 || w.Clients[0].Speed != 866 {
		t.Errorf("WLAN 1: %+v", w)
	}
	if w := info.WLANs[1]; w.Band != "5 GHz" || !w.Open {
		t.Errorf("Gast-WLAN (offen, 5 GHz): %+v", w)
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

// TestFaultDetail: UPnP-Fehlercode und -text werden aus der SOAP-Fehlerantwort gelesen.
func TestFaultDetail(t *testing.T) {
	body := []byte(`<s:Fault><detail><UPnPError><errorCode>606</errorCode><errorDescription>Action not authorized</errorDescription></UPnPError></detail></s:Fault>`)
	if got := faultDetail(500, body); got != "HTTP 500, UPnP 606 Action not authorized" {
		t.Errorf("faultDetail = %q", got)
	}
	if got := faultDetail(404, nil); got != "HTTP 404" {
		t.Errorf("faultDetail ohne Körper = %q", got)
	}
}
