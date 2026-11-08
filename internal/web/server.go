// Package web enthaelt den eingebauten Webserver samt Oberflaeche.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

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
	finished time.Time
}

// NewHandler baut den HTTP-Handler: Oberflaeche unter "/", Daten unter "/api/...".
func NewHandler(opt Options) http.Handler {
	s := &server{opt: opt, names: map[string]string{}}
	if opt.Demo {
		s.hosts = DemoHosts()
	}
	mux := http.NewServeMux()

	// Statische Dateien aus dem eingebetteten Ordner "static" ausliefern.
	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("GET /api/hosts", s.handleHosts)
	mux.HandleFunc("POST /api/hosts/name", s.handleRename)
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
	// Kopie bauen und Anzeigenamen des Nutzers einsetzen (Scan-Ergebnis bleibt unveraendert).
	hosts := make([]model.Host, len(s.hosts)) // JSON: [] statt null
	copy(hosts, s.hosts)
	for i := range hosts {
		if n, ok := s.names[hosts[i].IP]; ok {
			hosts[i].ScannedName = hosts[i].Name
			hosts[i].Name = n
			hosts[i].Known = true
			hosts[i].NameSource = "nutzer"
		}
	}
	writeJSON(w, http.StatusOK, hosts)
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
		hosts, err := scan.Run(ctx, scan.Options{Target: req.Target, Ports: ports, AllowPublic: s.opt.AllowPublic},
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
			return
		}
		s.hosts = hosts
	}()
	writeJSON(w, http.StatusAccepted, map[string]int{"total": len(ips)})
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
