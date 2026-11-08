package scan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// Zielauswertung: Groessen, Grenzen und Sperre oeffentlicher Adressen.
func TestExpandTarget(t *testing.T) {
	if ips, err := ExpandTarget("192.168.1.0/24", false); err != nil || len(ips) != 254 {
		t.Errorf("/24: %d IPs, err=%v (erwartet 254)", len(ips), err)
	}
	if ips, _ := ExpandTarget("10.0.0.0/30", false); len(ips) != 2 {
		t.Errorf("/30: %d IPs (erwartet 2)", len(ips))
	}
	if ips, _ := ExpandTarget("192.168.1.5", false); len(ips) != 1 {
		t.Errorf("Einzel-IP: %d", len(ips))
	}
	for _, bad := range []string{"", "abc", "8.8.8.8/32", "10.0.0.0/8", "::1"} {
		if _, err := ExpandTarget(bad, false); err == nil {
			t.Errorf("%q haette abgelehnt werden muessen", bad)
		}
	}
	if _, err := ExpandTarget("8.8.8.8", true); err != nil {
		t.Errorf("mit allowPublic muss 8.8.8.8 erlaubt sein: %v", err)
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("22, 80,8000-8002,80")
	if err != nil || len(got) != 5 { // 22,80,8000,8001,8002 (80 doppelt entfernt)
		t.Errorf("ParsePorts: %v err=%v", got, err)
	}
	for _, bad := range []string{"0", "70000", "a", "10-5"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q haette abgelehnt werden muessen", bad)
		}
	}
}

func TestARPParsing(t *testing.T) {
	linux := "IP address HW type Flags HW address Mask Device\n192.168.1.1 0x1 0x2 3c:a6:2f:11:22:33 * eth0\n192.168.1.9 0x1 0x0 00:00:00:00:00:00 * eth0\n"
	if m := parseLinuxARP(linux); len(m) != 1 || m["192.168.1.1"] != "3C:A6:2F:11:22:33" {
		t.Errorf("linux: %v", m)
	}
	win := "  192.168.1.10          00-11-32-aa-bb-cc     dynamisch\n  192.168.1.255         ff-ff-ff-ff-ff-ff     statisch\n"
	if m := parseARPCommand(win); len(m) != 1 || m["192.168.1.10"] != "00:11:32:AA:BB:CC" {
		t.Errorf("windows: %v", m)
	}
	mac := "? (192.168.1.23) at 0:1b:a9:44:55:66 on en0 ifscope [ethernet]\n"
	if m := parseARPCommand(mac); m["192.168.1.23"] != "00:1B:A9:44:55:66" {
		t.Errorf("macos: %v", m)
	}
}

func TestVendor(t *testing.T) {
	if Vendor("B8:27:EB:01:02:03") != "Raspberry Pi" {
		t.Error("Raspberry nicht erkannt")
	}
	if Vendor("DA:11:22:33:44:55") == "" {
		t.Error("lokale MAC nicht erkannt")
	}
}

// End-to-End gegen localhost: ein Test-Server mit SSH-Banner muss als offener Port
// samt Banner erscheinen, ein geschlossener Port nicht.
func TestRunLocalhost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-TestServer\r\n"))
			c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port
	// Einen garantiert geschlossenen Port finden: kurz oeffnen, wieder schliessen.
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	var lastDone int
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hosts, err := Run(ctx, Options{Target: "127.0.0.1", Ports: []int{openPort, closedPort}, Timeout: time.Second},
		func(done, total int) { lastDone = done })
	if err != nil {
		t.Fatal(err)
	}
	if lastDone != 1 {
		t.Errorf("Fortschritt: %d (erwartet 1)", lastDone)
	}
	if len(hosts) != 1 || len(hosts[0].Ports) != 1 {
		t.Fatalf("erwartet 1 Host mit 1 Port, bekam %+v", hosts)
	}
	p := hosts[0].Ports[0]
	if p.Number != openPort || p.Banner != "SSH-2.0-TestServer" {
		t.Errorf("Port/Banner falsch: %+v (erwartet %s)", p, strconv.Itoa(openPort))
	}
}

// Abbruch ueber den Context muss einen Fehler liefern.
func TestRunCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Options{Target: "127.0.0.1", Ports: []int{1}}, nil); err == nil {
		t.Error("abgebrochener Scan muss Fehler liefern")
	}
}

// Pseudonamen wie "_gateway" (NSS myhostname) duerfen nicht als Geraetename erscheinen;
// normale Namen bleiben erhalten (ohne Punkt am Ende).
func TestCleanHostName(t *testing.T) {
	for in, want := range map[string]string{
		"_gateway": "", "_Gateway.": "", "192.168.1.1": "", "fritz.box.": "fritz.box", "nas-01": "nas-01", "": "", "a\x00b": "ab",
	} {
		if got := cleanHostName(in); got != want {
			t.Errorf("cleanHostName(%q) = %q, erwartet %q", in, got, want)
		}
	}
}

// Zertifikatsname und HTTP-Titel werden von lokalen Test-Servern gelesen.
// (httptest-Zertifikat enthaelt den DNS-Namen "example.com".)
func TestCertNameAndTitle(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head>\n<TITLE> FRITZ!Box\n 7590 </TITLE></head></html>"))
	}))
	defer tlsSrv.Close()
	port := tlsSrv.Listener.Addr().(*net.TCPAddr).Port
	ctx := context.Background()
	if got := certName(ctx, "127.0.0.1", port); got != "example.com" {
		t.Errorf("certName = %q, erwartet example.com", got)
	}
	// httpTitle waehlt https nur fuer bekannte TLS-Ports; hier direkt per Klartext-Server pruefen.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<title>FRITZ!Box 7590</title>"))
	}))
	defer plain.Close()
	pport := plain.Listener.Addr().(*net.TCPAddr).Port
	if got := httpTitle(ctx, "127.0.0.1", pport); got != "FRITZ!Box 7590" {
		t.Errorf("httpTitle = %q", got)
	}
}
