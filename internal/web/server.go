// Package web enthaelt den eingebauten Webserver samt Oberflaeche.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/berion1982/netzscanner/internal/export"
	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/scan"
	"github.com/berion1982/netzscanner/internal/version"
)

// Die Oberflaeche (HTML/JS/CSS) wird ins Programm eingebettet:
// dadurch genuegt eine einzige Datei zur Verteilung.
//
//go:embed static
var staticFiles embed.FS

// Options steuert den Server.
type Options struct {
	Demo        bool // Demo-Daten anzeigen, solange noch kein Scan lief
	AllowPublic bool // Scans oeffentlicher Adressen erlauben
}

// server haelt den Zustand des (einen) laufenden bzw. letzten Scans.
type server struct {
	opt Options

	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	target   string
	done     int
	total    int
	errMsg   string
	hosts    []model.Host
	names    map[string]string // vom Nutzer vergebene Anzeigenamen: IP -> Name (nur im RAM)
	users    map[string]string // vom Nutzer eingetragene Benutzernamen: IP -> Name (nur im RAM, KEINE Passwoerter)
	finished time.Time
}

// NewHandler baut den HTTP-Handler: Oberflaeche unter "/", Daten unter "/api/...".
func NewHandler(opt Options) http.Handler {
	s := &server{opt: opt, names: map[string]string{}, users: map[string]string{}}
	if opt.Demo {
		s.hosts = DemoHosts()
	}
	mux := http.NewServeMux()

	// Statische Dateien aus dem eingebetteten Ordner "static" ausliefern.
	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("GET /api/hosts", s.handleHosts)
	mux.HandleFunc("POST /api/hosts/name", s.handleRename)
	mux.HandleFunc("POST /api/hosts/user", s.handleUser)
	mux.HandleFunc("POST /api/export", s.handleExport)
	mux.HandleFunc("POST /api/export/topology-pdf", s.handleTopologyPDF)
	mux.HandleFunc("GET /api/networks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, scan.LocalNetworks())
	})
	mux.HandleFunc("GET /api/scan", s.handleStatus)
	mux.HandleFunc("POST /api/scan", s.handleStart)
	mux.HandleFunc("POST /api/scan/cancel", s.handleCancel)
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"version": version.Version, "buildDate": version.BuildDate, "commit": version.Commit,
		})
	})
	return guardPost(mux)
}

// guardPost schuetzt die schreibenden Aufrufe: Eine fremde Webseite im Browser
// koennte sonst per Formular/fetch einen Scan an http://localhost:8484 ausloesen
// (CSRF). Wir verlangen Content-Type JSON (loest im Browser einen Preflight aus,
// den wir nie freigeben) und pruefen, dass ein evtl. Origin-Header zum Host passt.
func guardPost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				writeJSON(w, http.StatusUnsupportedMediaType, errBody("Content-Type application/json erforderlich"))
				return
			}
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					writeJSON(w, http.StatusForbidden, errBody("fremder Origin"))
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleHosts(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.viewLocked())
}

// viewLocked liefert eine Kopie der Geraeteliste mit den Eingaben des Nutzers
// (Anzeigename, Benutzername). Das Scan-Ergebnis selbst bleibt unveraendert.
// Aufrufer muss s.mu halten.
func (s *server) viewLocked() []model.Host {
	hosts := make([]model.Host, len(s.hosts)) // JSON: [] statt null
	copy(hosts, s.hosts)
	for i := range hosts {
		if n, ok := s.names[hosts[i].IP]; ok {
			hosts[i].ScannedName = hosts[i].Name
			hosts[i].Name = n
			hosts[i].Known = true
			hosts[i].NameSource = "nutzer"
		}
		hosts[i].Username = s.users[hosts[i].IP]
	}
	return hosts
}

// maxNameRunes ist die maximale Laenge eines Anzeigenamens.
const maxNameRunes = 64

// cleanName prueft einen vom Nutzer eingegebenen Namen: getrimmt, hoechstens
// 64 Zeichen, keine Steuerzeichen (z.B. Zeilenumbrueche - wichtig fuer CSV/Lesezeichen).
func cleanName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxNameRunes {
		return "", fmt.Errorf("Name zu lang (maximal %d Zeichen)", maxNameRunes)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("Name enthaelt unzulaessige Zeichen")
		}
	}
	return s, nil
}

// handleRename setzt den Anzeigenamen eines gefundenen Geraets; leerer Name = zuruecksetzen.
// Die Namen bleiben ueber neue Scans hinweg (nach IP) erhalten, aber nur bis das Programm endet.
func (s *server) handleRename(w http.ResponseWriter, r *http.Request) {
	var req struct{ IP, Name string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	name, err := cleanName(req.Name)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, h := range s.hosts {
		if h.IP == req.IP {
			found = true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("Geraet nicht in der Liste"))
		return
	}
	if name == "" {
		delete(s.names, req.IP)
	} else {
		s.names[req.IP] = name
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"running": s.running, "target": s.target, "done": s.done, "total": s.total,
		"error": s.errMsg, "hosts": len(s.hosts), "finished": s.finished,
	})
}

// handleStart startet einen Scan im Hintergrund (nur einer gleichzeitig).
func (s *server) handleStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
		Ports  string `json:"ports"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	ports, err := scan.ParsePorts(req.Ports)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	// Ziel vorab pruefen, damit Fehler sofort zurueckkommen (nicht erst im Hintergrund).
	ips, err := scan.ExpandTarget(req.Target, s.opt.AllowPublic)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		writeJSON(w, http.StatusConflict, errBody("es laeuft bereits ein Scan"))
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.running, s.cancel, s.target = true, cancel, req.Target
	s.done, s.total, s.errMsg, s.hosts = 0, len(ips), "", nil
	s.mu.Unlock()

	go func() {
		hosts, err := scan.Run(ctx, scan.Options{Target: req.Target, Ports: ports, AllowPublic: s.opt.AllowPublic,
			OnHost: s.upsertHost}, // Teilergebnisse sofort in die Liste (I-044)
			func(done, total int) {
				s.mu.Lock()
				s.done, s.total = done, total
				s.mu.Unlock()
			})
		s.mu.Lock()
		defer s.mu.Unlock()
		s.running, s.finished = false, time.Now()
		if err != nil {
			s.errMsg = "Scan abgebrochen: " + err.Error()
			// Bisher gefundene Teilergebnisse bleiben sichtbar, werden aber abgeschlossen
			// (kein "wird ermittelt" mehr, Name ggf. "(unbekannt)").
			for i := range s.hosts {
				s.hosts[i] = scan.FinishHost(s.hosts[i])
			}
			return
		}
		s.hosts = hosts
	}()
	writeJSON(w, http.StatusAccepted, map[string]int{"total": len(ips)})
}

// upsertHost nimmt ein Teilergebnis des laufenden Scans auf (I-044): Ist die IP schon
// in der Liste, werden die Angaben ersetzt, sonst wird das Geraet einsortiert. Die
// Liste bleibt nach IP sortiert. Nach Scan-Ende oder Abbruch wird sie ignoriert,
// damit ein spaet eintreffendes Teilergebnis das Endergebnis nicht ueberschreibt.
func (s *server) upsertHost(h model.Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	for i := range s.hosts {
		if s.hosts[i].IP == h.IP {
			s.hosts[i] = h
			return
		}
	}
	s.hosts = append(s.hosts, h)
	sort.Slice(s.hosts, func(i, j int) bool { return ipLess(s.hosts[i].IP, s.hosts[j].IP) })
}

// ipLess sortiert IPv4-Adressen numerisch (Fallback: Text).
func ipLess(a, b string) bool {
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	if errX != nil || errY != nil {
		return a < b
	}
	return x.Less(y)
}

func (s *server) handleCancel(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

// writeJSON schreibt v als JSON; "no-store" verhindert Caching sensibler Netzdaten.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleUser traegt den Benutzernamen fuer ein Geraet ein (leer = loeschen).
// Nur der NAME wird gespeichert - Passwoerter nimmt dieses Programm hier nicht an.
func (s *server) handleUser(w http.ResponseWriter, r *http.Request) {
	var req struct{ IP, User string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	user, err := cleanName(req.User)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(strings.Replace(err.Error(), "Name", "Benutzername", 1)))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasHostLocked(req.IP) {
		writeJSON(w, http.StatusNotFound, errBody("Geraet nicht in der Liste"))
		return
	}
	if user == "" {
		delete(s.users, req.IP)
	} else {
		s.users[req.IP] = user
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// hasHostLocked prueft, ob die IP in der aktuellen Liste steht. Aufrufer haelt s.mu.
func (s *server) hasHostLocked(ip string) bool {
	for _, h := range s.hosts {
		if h.IP == ip {
			return true
		}
	}
	return false
}

// handleExport erzeugt eine Datei aus den ausgewaehlten Geraeten und liefert sie als Download.
// format: "csv-excel" (; + BOM), "csv" (Komma), "html", "md", "bookmarks" (Lesezeichenleiste) oder "bookmarks-folder".
func (s *server) handleExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Format string   `json:"format"`
		IPs    []string `json:"ips"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	s.mu.Lock()
	view, target := s.viewLocked(), s.target
	s.mu.Unlock()

	// Nur ausgewaehlte, tatsaechlich vorhandene Geraete - in der Reihenfolge der Liste.
	want := map[string]bool{}
	for _, ip := range req.IPs {
		want[ip] = true
	}
	var chosen []model.Host
	for _, h := range view {
		if want[h.IP] {
			chosen = append(chosen, h)
			delete(want, h.IP)
		}
	}
	if len(want) > 0 {
		writeJSON(w, http.StatusBadRequest, errBody("ausgewaehlte Geraete nicht in der Liste"))
		return
	}
	if len(chosen) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("keine Geraete ausgewaehlt"))
		return
	}

	meta := export.Meta{Target: target, Generated: time.Now(), Version: version.String()}
	var buf bytes.Buffer
	var ctype, ext string
	var err error
	switch req.Format {
	case "csv-excel":
		ctype, ext, err = "text/csv; charset=utf-8", "csv", export.WriteCSV(&buf, chosen, true)
	case "csv":
		ctype, ext, err = "text/csv; charset=utf-8", "csv", export.WriteCSV(&buf, chosen, false)
	case "html":
		ctype, ext, err = "text/html; charset=utf-8", "html", export.WriteHTML(&buf, chosen, meta)
	case "md":
		ctype, ext, err = "text/markdown; charset=utf-8", "md", export.WriteMarkdown(&buf, chosen, meta)
	case "bookmarks", "bookmarks-folder":
		// Lesezeichen brauchen mindestens einen Web-Link (Geraet mit offenem Web-Port).
		if export.BookmarkCount(chosen) == 0 {
			writeJSON(w, http.StatusBadRequest, errBody("keine Web-Links bei den ausgewaehlten Geraeten"))
			return
		}
		ctype, ext = "text/html; charset=utf-8", "html"
		err = export.WriteBookmarks(&buf, chosen, meta, req.Format == "bookmarks")
	default:
		writeJSON(w, http.StatusBadRequest, errBody("unbekanntes Format"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("Export fehlgeschlagen"))
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="netzscanner-`+meta.Generated.Format("20060102-1504")+`.`+ext+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())
}

// handleTopologyPDF liefert die Topologie (Karte + Geraeteliste) ALLER Geraete als PDF-Download (I-012).
// Anders als /api/export braucht es keine Auswahl; Zugangsdaten sind nicht enthalten.
func (s *server) handleTopologyPDF(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	view, target := s.viewLocked(), s.target
	s.mu.Unlock()
	if len(view) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("keine Geraete in der Liste"))
		return
	}
	meta := export.Meta{Target: target, Generated: time.Now(), Version: version.String()}
	var buf bytes.Buffer
	if err := export.WritePDF(&buf, view, meta); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("PDF-Export fehlgeschlagen"))
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="netzscanner-topologie-`+meta.Generated.Format("20060102-1504")+`.pdf"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())
}
