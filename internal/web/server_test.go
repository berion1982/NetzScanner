package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
)

// Startseite und API muessen antworten; die Demo-Daten enthalten Web-Links.
func TestHandlerDemo(t *testing.T) {
	h := NewHandler(Options{Demo: true})
	for path, want := range map[string]string{"/": "NetzScanner", "/api/hosts": "webLinks", "/api/version": "buildDate", "/api/scan": "running"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: Status %d, enthaelt %q nicht", path, rec.Code, want)
		}
	}
}

// Ohne Demo-Modus ist die Liste leer ("[]", nicht "null").
func TestHostsEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(Options{}).ServeHTTP(rec, httptest.NewRequest("GET", "/api/hosts", nil))
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("erwartet [], bekam %q", rec.Body.String())
	}
}

// POST-Schutz: ohne JSON-Content-Type und mit fremdem Origin wird abgelehnt.
func TestPostGuard(t *testing.T) {
	h := NewHandler(Options{})
	r := httptest.NewRequest("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1"}`))
	r.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 415 {
		t.Errorf("text/plain: Status %d (erwartet 415)", rec.Code)
	}
	r = httptest.NewRequest("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://evil.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Errorf("fremder Origin: Status %d (erwartet 403)", rec.Code)
	}
}

// Ungueltige/oeffentliche Ziele werden sofort mit 400 abgelehnt.
func TestStartRejectsBadTarget(t *testing.T) {
	h := NewHandler(Options{})
	for _, body := range []string{`{"target":"8.8.8.8"}`, `{"target":"x"}`, `{"target":"127.0.0.1","ports":"99999"}`} {
		r := httptest.NewRequest("POST", "/api/scan", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != 400 {
			t.Errorf("%s: Status %d (erwartet 400)", body, rec.Code)
		}
	}
}

// Kompletter Ablauf: Scan starten, warten bis fertig, Ergebnis abrufen.
func TestScanFlow(t *testing.T) {
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

	h := NewHandler(Options{})
	r := httptest.NewRequest("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1","ports":"`+strconv.Itoa(port)+`"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 202 {
		t.Fatalf("Start: Status %d, %s", rec.Code, rec.Body.String())
	}
	for i := 0; i < 100; i++ { // bis zu 10 s warten
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/scan", nil))
		if strings.Contains(rec.Body.String(), `"running":false`) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/hosts", nil))
	if !strings.Contains(rec.Body.String(), "127.0.0.1") || !strings.Contains(rec.Body.String(), strconv.Itoa(port)) {
		t.Errorf("Ergebnis enthaelt Host/Port nicht: %s", rec.Body.String())
	}
}

// postJSON ist ein kleiner Helfer fuer JSON-POSTs in Tests.
func postJSON(h http.Handler, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// Umbenennen: Name wird angezeigt, Originalname bleibt als scannedName, Reset funktioniert,
// unbekannte IPs und unzulaessige Namen werden abgelehnt.
func TestRename(t *testing.T) {
	h := NewHandler(Options{Demo: true})
	get := func() string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/hosts", nil))
		return rec.Body.String()
	}
	if rec := postJSON(h, "/api/hosts/name", `{"ip":"192.168.1.10","name":"  NAS Büro  "}`); rec.Code != 200 {
		t.Fatalf("Umbenennen: Status %d %s", rec.Code, rec.Body.String())
	}
	if out := get(); !strings.Contains(out, `"name":"NAS Büro"`) || !strings.Contains(out, `"scannedName":"nas-01"`) {
		t.Errorf("Name nicht uebernommen: %s", out)
	}
	if rec := postJSON(h, "/api/hosts/name", `{"ip":"192.168.1.10","name":""}`); rec.Code != 200 {
		t.Fatalf("Reset: Status %d", rec.Code)
	}
	if out := get(); strings.Contains(out, "NAS Büro") || strings.Contains(out, "scannedName") {
		t.Errorf("Reset hat nicht gewirkt: %s", out)
	}
	for body, want := range map[string]int{
		`{"ip":"10.9.9.9","name":"x"}`:                                   404,
		`{"ip":"192.168.1.10","name":"a\nb"}`:                            400,
		`{"ip":"192.168.1.10","name":"` + strings.Repeat("x", 65) + `"}`: 400,
	} {
		if rec := postJSON(h, "/api/hosts/name", body); rec.Code != want {
			t.Errorf("%.40s: Status %d (erwartet %d)", body, rec.Code, want)
		}
	}
}

// Benutzername setzen -> erscheint in der Liste und im CSV-Export; Passwoerter gibt es nirgends.
func TestExportFlow(t *testing.T) {
	h := NewHandler(Options{Demo: true})
	if rec := postJSON(h, "/api/hosts/user", `{"ip":"192.168.1.10","user":"admin"}`); rec.Code != 200 {
		t.Fatalf("Benutzername: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postJSON(h, "/api/hosts/name", `{"ip":"192.168.1.10","name":"NAS Büro"}`); rec.Code != 200 {
		t.Fatalf("Name: %d", rec.Code)
	}
	rec := postJSON(h, "/api/export", `{"format":"csv","ips":["192.168.1.10","192.168.1.1"]}`)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), ".csv") {
		t.Fatalf("Export: %d %v", rec.Code, rec.Header())
	}
	out := rec.Body.String()
	// Reihenfolge der Liste (fritz.box zuerst), nur die zwei ausgewaehlten Geraete.
	if !strings.Contains(out, ",192.168.1.1,3C:A6:2F:11:22:33,AVM,fritz.box,") ||
		!strings.Contains(out, "admin,192.168.1.10,00:11:32:AA:BB:CC,Synology,NAS Büro,") || strings.Contains(out, "192.168.1.23") {
		t.Errorf("CSV-Inhalt falsch: %q", out)
	}
	for _, f := range []string{"csv-excel", "html", "md"} {
		if rec := postJSON(h, "/api/export", `{"format":"`+f+`","ips":["192.168.1.1"]}`); rec.Code != 200 || rec.Body.Len() == 0 {
			t.Errorf("Format %s: Status %d", f, rec.Code)
		}
	}
	for body, want := range map[string]int{
		`{"format":"csv","ips":[]}`:              400, // nichts ausgewaehlt
		`{"format":"csv","ips":["10.9.9.9"]}`:    400, // unbekanntes Geraet
		`{"format":"xls","ips":["192.168.1.1"]}`: 400, // unbekanntes Format
	} {
		if rec := postJSON(h, "/api/export", body); rec.Code != want {
			t.Errorf("%s: Status %d (erwartet %d)", body, rec.Code, want)
		}
	}
	if rec := postJSON(h, "/api/hosts/user", `{"ip":"10.9.9.9","user":"x"}`); rec.Code != 404 {
		t.Errorf("unbekannte IP: %d", rec.Code)
	}
}

// I-044: Teilergebnisse werden einsortiert (nach IP, numerisch), bei gleicher IP
// ersetzt und nach Scan-Ende ignoriert.
func TestUpsertHost(t *testing.T) {
	s := &server{names: map[string]string{}, users: map[string]string{}, running: true}
	s.upsertHost(model.Host{IP: "192.168.1.100", Name: "b", Pending: true})
	s.upsertHost(model.Host{IP: "192.168.1.9", Name: "a"})
	s.upsertHost(model.Host{IP: "192.168.1.100", Name: "b-fertig"}) // ersetzt, kein Duplikat
	if len(s.hosts) != 2 || s.hosts[0].IP != "192.168.1.9" || s.hosts[1].Name != "b-fertig" || s.hosts[1].Pending {
		t.Fatalf("falsche Liste: %+v", s.hosts)
	}
	s.running = false
	s.upsertHost(model.Host{IP: "192.168.1.5"}) // Scan vorbei: ignoriert
	if len(s.hosts) != 2 {
		t.Errorf("Teilergebnis nach Scan-Ende darf nicht aufgenommen werden: %+v", s.hosts)
	}
}

// Standort setzen -> erscheint in /api/hosts und in der CSV; Fehlerfaelle werden abgewiesen.
func TestLocation(t *testing.T) {
	h := NewHandler(Options{Demo: true})
	if rec := postJSON(h, "/api/hosts/location", `{"ip":"192.168.1.10","location":"Büro, Raum 2"}`); rec.Code != 200 {
		t.Fatalf("Standort: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postJSON(h, "/api/hosts/location", `{"ip":"10.9.9.9","location":"x"}`); rec.Code != 404 {
		t.Errorf("unbekannte IP: %d", rec.Code)
	}
	if rec := postJSON(h, "/api/hosts/location", `{"ip":"192.168.1.10","location":"a\u0007b"}`); rec.Code != 400 {
		t.Errorf("Steuerzeichen: %d", rec.Code)
	}
	rec := postJSON(h, "/api/export", `{"format":"csv","ips":["192.168.1.10"]}`)
	if !strings.Contains(rec.Body.String(), `"Büro, Raum 2"`) {
		t.Errorf("Standort fehlt in der CSV: %q", rec.Body.String())
	}
	// Leer = loeschen
	postJSON(h, "/api/hosts/location", `{"ip":"192.168.1.10","location":""}`)
	rec = postJSON(h, "/api/export", `{"format":"csv","ips":["192.168.1.10"]}`)
	if strings.Contains(rec.Body.String(), "Büro") {
		t.Errorf("Standort nicht geloescht: %q", rec.Body.String())
	}
}

// Kategorie: automatische Vermutung, Setzen durch den Nutzer, Zuruecksetzen, Fehlerfaelle.
func TestCategory(t *testing.T) {
	h := NewHandler(Options{Demo: true})
	cat := func(ip string) (string, bool) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/hosts", nil))
		var hs []model.Host
		if err := json.Unmarshal(rec.Body.Bytes(), &hs); err != nil {
			t.Fatal(err)
		}
		for _, x := range hs {
			if x.IP == ip {
				return x.Category, x.CategoryManual
			}
		}
		t.Fatalf("Geraet %s fehlt", ip)
		return "", false
	}
	if c, m := cat("192.168.1.1"); c != model.CatNetwork || m {
		t.Errorf("Router automatisch: %q manuell=%v", c, m)
	}
	if c, _ := cat("192.168.1.10"); c != model.CatServer { // Synology-NAS
		t.Errorf("NAS: %q", c)
	}
	if rec := postJSON(h, "/api/hosts/category", `{"ip":"192.168.1.10","category":"iot"}`); rec.Code != 200 {
		t.Fatalf("Kategorie setzen: %d", rec.Code)
	}
	if c, m := cat("192.168.1.10"); c != model.CatIoT || !m {
		t.Errorf("manuell: %q %v", c, m)
	}
	if rec := postJSON(h, "/api/hosts/category", `{"ip":"192.168.1.10","category":"kaffee"}`); rec.Code != 400 {
		t.Errorf("ungueltige Kategorie: %d", rec.Code)
	}
	if rec := postJSON(h, "/api/hosts/category", `{"ip":"10.9.9.9","category":"iot"}`); rec.Code != 404 {
		t.Errorf("unbekannte IP: %d", rec.Code)
	}
	postJSON(h, "/api/hosts/category", `{"ip":"192.168.1.10","category":"auto"}`)
	if c, m := cat("192.168.1.10"); c != model.CatServer || m {
		t.Errorf("zurueckgesetzt: %q %v", c, m)
	}
}

// Zwischenspeicher (I-016): Eingaben ueberleben einen Neustart; IP-Wechsel, kaputte Datei, Loeschen.
func TestStorePersistence(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sub", "eingaben.json")
	host := model.Host{IP: "192.168.1.50", Name: "pc", MAC: "AA:BB:CC:00:00:01"}
	newSrv := func() *server { // wie NewHandler, aber mit Zugriff auf den Server
		s := &server{opt: Options{DataFile: file}, names: map[string]string{}, users: map[string]string{},
			locs: map[string]string{}, cats: map[string]string{}, macs: map[string]string{}}
		s.loadStore()
		s.hosts = []model.Host{host}
		return s
	}
	s := newSrv()
	s.mu.Lock()
	s.claimLocked(host.IP)
	s.names[host.IP], s.locs[host.IP], s.cats[host.IP] = "Büro-PC", "Raum 2", model.CatClient
	s.persistLocked()
	s.mu.Unlock()
	if st, err := os.Stat(file); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("Datei fehlt oder Rechte falsch: %v %v", err, st)
	}

	// Neustart: Eingaben sind wieder da.
	s2 := newSrv()
	v := s2.viewLocked()
	if v[0].Name != "Büro-PC" || v[0].Location != "Raum 2" || v[0].Category != model.CatClient || !v[0].CategoryManual {
		t.Errorf("nach Neustart: %+v", v[0])
	}
	// Anderes Geraet hinter derselben IP: Eingaben gelten nicht.
	s2.hosts[0].MAC = "AA:BB:CC:00:00:99"
	if v := s2.viewLocked(); v[0].Location != "" || v[0].Name == "Büro-PC" {
		t.Errorf("IP-Wechsel nicht erkannt: %+v", v[0])
	}
	// Kaputte Datei: wird umbenannt, nichts geladen, kein Absturz.
	if err := os.WriteFile(file, []byte("{kaputt"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3 := newSrv()
	if len(s3.names) != 0 {
		t.Error("kaputte Datei darf nichts laden")
	}
	if _, err := os.Stat(file + ".defekt"); err != nil {
		t.Errorf("kaputte Datei nicht umbenannt: %v", err)
	}
	// Loeschen entfernt RAM und Datei.
	s2.mu.Lock()
	s2.persistLocked()
	s2.clearStoreLocked()
	s2.mu.Unlock()
	if _, err := os.Stat(file); !os.IsNotExist(err) || len(s2.names) != 0 {
		t.Errorf("Loeschen unvollstaendig: %v", err)
	}
}

// Ohne DataFile (Standard in Tests, --no-save, Demo) wird nie eine Datei geschrieben.
func TestNoStoreWithoutFile(t *testing.T) {
	h := NewHandler(Options{Demo: true})
	if rec := postJSON(h, "/api/hosts/location", `{"ip":"192.168.1.10","location":"x"}`); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
}
