package scan

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
)

// I-046: Bereiche und Listen im Ziel-Feld.
func TestExpandTargetRanges(t *testing.T) {
	count := func(in string) int {
		ips, err := ExpandTarget(in, false)
		if err != nil {
			return -1
		}
		return len(ips)
	}
	for in, want := range map[string]int{
		"192.168.1.10-50": 41, "192.168.1.10-192.168.1.50": 41, "192.168.1.250-192.168.2.5": 12,
		"192.168.1.5-5": 1, " 192.168.1.5 , 192.168.1.5 ": 1, // Duplikate entfallen
		"192.168.1.5, 192.168.1.20-22": 4, "192.168.1.0/30, 192.168.1.9": 3,
		"192.168.0.0-192.168.255.255": MaxTargets,
	} {
		if got := count(in); got != want {
			t.Errorf("ExpandTarget(%q) = %d, erwartet %d", in, got, want)
		}
	}
	for _, bad := range []string{
		"192.168.1.50-10", "192.168.1.10-300", "192.168.1.10-", "-5", "192.168.1.x-5", "192.168.1.1,", ",192.168.1.1",
		"192.168.1.1-::1", "10.0.0.0-10.2.0.0", "192.168.1.1, 8.8.8.8", "192.168.255.250-193.0.0.5", // Bereich ueber die Privatgrenze
		"192.168.0.0/16, 10.0.0.0/16", // zusammen > MaxTargets
	} {
		if _, err := ExpandTarget(bad, false); err == nil {
			t.Errorf("%q haette abgelehnt werden muessen", bad)
		}
	}
}

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
	// Die volle IEEE-Liste nennt den Namen "Raspberry Pi Trading Ltd" -> Teilstring pruefen.
	if !strings.Contains(Vendor("B8:27:EB:01:02:03"), "Raspberry Pi") {
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
		// I-009: MAC-/EUI-64-artige Kennungen sind keine Namen.
		"001788FFFE476CE2": "", "00:17:88:47:6c:e2": "", "001788FFFE476CE2.fritz.box": "", "A1B2C3D4E5F6": "",
		"hue-bridge": "hue-bridge", "cafe": "cafe", "001788FFFE476CEZ": "001788FFFE476CEZ",
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

// summarizeCert: abgelaufen, selbst signiert und Tage bis Ablauf werden richtig erkannt.
func TestSummarizeCert(t *testing.T) {
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	name := pkix.Name{CommonName: "fritz.box"}
	c := &x509.Certificate{Subject: name, Issuer: name, NotAfter: now.Add(10 * 24 * time.Hour)}
	got := summarizeCert(c, now)
	if got.Subject != "fritz.box" || !got.SelfSigned || got.Expired || got.DaysLeft != 10 || got.NotAfter != "2026-11-18" {
		t.Errorf("unerwartet: %+v", got)
	}
	c.NotAfter = now.Add(-48 * time.Hour)
	c.Issuer = pkix.Name{CommonName: "CA"}
	got = summarizeCert(c, now)
	if !got.Expired || got.DaysLeft != -2 || got.SelfSigned {
		t.Errorf("abgelaufen falsch: %+v", got)
	}
}

// parseOUI/macPrefix: Kommentare, defekte Zeilen und verschiedene MAC-Schreibweisen.
func TestParseOUIAndPrefix(t *testing.T) {
	m := parseOUI("# Kommentar\naabbcc;Test GmbH\nkaputt\nAABB;zu kurz\n")
	if len(m) != 1 || m["AABBCC"] != "Test GmbH" {
		t.Errorf("parseOUI falsch: %v", m)
	}
	for _, mac := range []string{"b8:27:eb:01:02:03", "B8-27-EB-01-02-03", "b827.eb01.0203", "B827EB010203"} {
		if got := macPrefix(mac); got != "B827EB" {
			t.Errorf("macPrefix(%q) = %q", mac, got)
		}
	}
	if macPrefix("zz:11") != "" || macPrefix("B8:27") != "" {
		t.Error("ungueltige MAC muss leer ergeben")
	}
	if Vendor("") != "" {
		t.Error("leere MAC darf keinen Hersteller liefern")
	}
}

// udpServer startet einen lokalen UDP-Server, der auf jedes Paket mit reply(request) antwortet.
func udpServer(t *testing.T, reply func(req []byte) []byte) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("UDP nicht moeglich:", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(reply(buf[:n]), addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// mDNS: Antwort mit PTR "annas-iphone.local" (Kompressionszeiger auf die Frage) -> "annas-iphone".
func TestMDNSName(t *testing.T) {
	port := udpServer(t, func(req []byte) []byte {
		resp := append([]byte{}, req...)
		resp[2], resp[7] = 0x84, 1                               // Antwort-Flags, ANCOUNT = 1
		resp = append(resp, 0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 120) // Name=Zeiger auf Frage, PTR, IN, TTL
		rdata := append([]byte{12}, "annas-iphone"...)
		rdata = append(rdata, 5)
		rdata = append(rdata, "local"...)
		rdata = append(rdata, 0)
		resp = append(resp, byte(len(rdata)>>8), byte(len(rdata)))
		return append(resp, rdata...)
	})
	if got := mdnsName(context.Background(), "127.0.0.1", port); got != "annas-iphone" {
		t.Errorf("mdnsName = %q", got)
	}
}

// NetBIOS: Antwort mit Gruppenname "WORKGROUP" und eindeutigem Namen "DESKTOP-ABC" -> "DESKTOP-ABC".
func TestNetbiosName(t *testing.T) {
	entry := func(name string, suffix byte, flags uint16) []byte {
		e := []byte(name + strings.Repeat(" ", 15-len(name)))
		return append(e, suffix, byte(flags>>8), byte(flags))
	}
	port := udpServer(t, func(req []byte) []byte {
		resp := make([]byte, 12)
		resp[7] = 1 // ANCOUNT = 1
		resp = append(resp, req[12:12+34]...)
		resp = append(resp, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 37) // Typ, Klasse, TTL, Laenge
		resp = append(resp, 2)                                // 2 Namen
		resp = append(resp, entry("WORKGROUP", 0x00, 0x8400)...)
		return append(resp, entry("DESKTOP-ABC", 0x00, 0x0400)...)
	})
	if got := netbiosName(context.Background(), "127.0.0.1", port); got != "DESKTOP-ABC" {
		t.Errorf("netbiosName = %q", got)
	}
	if len(nbstatQuery()) != 50 {
		t.Errorf("NBSTAT-Anfrage hat falsche Laenge %d", len(nbstatQuery()))
	}
}

// Kaputte/manipulierte Antworten duerfen nicht abstuerzen oder haengen.
func TestUDPParsersRobust(t *testing.T) {
	for _, bad := range [][]byte{nil, {1, 2, 3}, make([]byte, 12), append(make([]byte, 12), 0xC0, 12)} {
		parsePTRAnswer(bad)
		parseNBSTAT(bad)
	}
	loop := append(make([]byte, 12), 0xC0, 12) // Zeiger auf sich selbst
	if _, ok := readName(loop, 12); ok {
		t.Error("Zeigerschleife muss abgelehnt werden")
	}
}

// I-044: Teilergebnisse. Der Callback meldet das Geraet zuerst mit Ports und
// "Pending", am Ende mit fertigem Namen (Pending=false); die letzte Meldung
// entspricht dem Endergebnis.
func TestRunPartialResults(t *testing.T) {
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
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	var mu sync.Mutex
	var events []model.Host
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hosts, err := Run(ctx, Options{Target: "127.0.0.1", Ports: []int{port}, Timeout: time.Second,
		OnHost: func(h model.Host) { mu.Lock(); events = append(events, h); mu.Unlock() }}, nil)
	if err != nil || len(hosts) != 1 {
		t.Fatalf("Run: %v, %+v", err, hosts)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) < 2 {
		t.Fatalf("erwartet mindestens 2 Teilergebnisse, bekam %d", len(events))
	}
	first, last := events[0], events[len(events)-1]
	if !first.Pending || len(first.Ports) != 1 || first.Name != pendingName {
		t.Errorf("erste Meldung muss Ports + Pending haben: %+v", first)
	}
	if last.Pending || last.Name == pendingName || last.Name != hosts[0].Name {
		t.Errorf("letzte Meldung muss fertig sein und dem Endergebnis entsprechen: %+v / %+v", last, hosts[0])
	}
	if hosts[0].Pending {
		t.Error("Endergebnis darf nicht Pending sein")
	}
}

// Gateway-Erkennung (I-010): Beispieltexte der drei Betriebssysteme.
func TestGatewayParsers(t *testing.T) {
	linux := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nwlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\nwlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n"
	if g := parseLinuxRoute(linux); g != "192.168.1.1" {
		t.Errorf("Linux: %q", g)
	}
	win := "Active Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.178.1  192.168.178.20     25\n"
	if g := parseWindowsRoute(win); g != "192.168.178.1" {
		t.Errorf("Windows: %q", g)
	}
	mac := "   route to: default\ndestination: default\n       mask: default\n    gateway: 10.0.0.1\n  interface: en0\n"
	if g := parseDarwinRoute(mac); g != "10.0.0.1" {
		t.Errorf("macOS: %q", g)
	}
	if g := parseLinuxRoute("Iface\tDestination\n"); g != "" {
		t.Errorf("leer: %q", g)
	}
}

func TestApplyGateway(t *testing.T) {
	hs := []model.Host{{IP: "192.168.1.1", MAC: "AA"}, {IP: "192.168.1.5", MAC: "BB"}, {IP: "10.0.0.9"}}
	ApplyGateway(hs, "192.168.1.1")
	if hs[0].Role != "router" || hs[0].Uplink != "" {
		t.Errorf("Router falsch: %+v", hs[0])
	}
	if hs[1].Uplink != "192.168.1.1" {
		t.Errorf("Uplink fehlt: %+v", hs[1])
	}
	if hs[2].Uplink != "" {
		t.Errorf("Geraet ohne MAC darf keinen Uplink haben: %+v", hs[2])
	}
	// Gateway nicht gefunden -> nichts aendern.
	hs2 := []model.Host{{IP: "192.168.1.5", MAC: "BB"}}
	ApplyGateway(hs2, "192.168.1.1")
	if hs2[0].Uplink != "" {
		t.Errorf("ohne Router kein Uplink: %+v", hs2[0])
	}
}
