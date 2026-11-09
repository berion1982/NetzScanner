package web

// Zwischenspeicher fuer die Eingaben des Nutzers (I-016).
//
// Gespeichert werden NUR Anzeigename, Benutzername (kein Passwort!), Standort und
// Kategorie je Geraet - keine Scan-Ergebnisse, keine Zugangsdaten. Die Datei
// wird nach jeder Aenderung atomar neu geschrieben (Temp-Datei + Umbenennen),
// damit ein Absturz oder Stromausfall sie nicht halb beschreibt.
// Rechte: Datei 0600, Ordner 0700 (nur der eigene Benutzer).

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/berion1982/netzscanner/internal/model"
)

// Grenzen gegen kaputte oder manipulierte Dateien.
const (
	maxStoreBytes   = 1 << 20 // 1 MiB
	maxStoreEntries = 5000
	storeVersion    = 1
)

// storeEntry sind die Eingaben zu einem Geraet. MAC dient als Schutz vor IP-Wechsel:
// Hat sich hinter der IP ein anderes Geraet (andere MAC) angemeldet, gelten die Eingaben nicht.
type storeEntry struct {
	MAC      string `json:"mac,omitempty"`
	Name     string `json:"name,omitempty"`
	User     string `json:"user,omitempty"`
	Location string `json:"location,omitempty"`
	Category string `json:"category,omitempty"`
}

// storeFile ist der Aufbau der JSON-Datei.
type storeFile struct {
	Version int                   `json:"version"`
	Entries map[string]storeEntry `json:"entries"` // Schluessel = IP
	// Custom: eigene Kategorien (Schluessel "custom:<Name>"); auch ohne zugeordnete Geraete gemerkt (I-017).
	Custom []string `json:"customCategories,omitempty"`
}

// DefaultStorePath liefert den Standardpfad (Konfigurationsordner des Benutzers), "" wenn unbekannt.
func DefaultStorePath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "netzscanner", "eingaben.json")
}

// loadStore liest die Datei (falls vorhanden) in die Maps des Servers. Fehler fuehren nie
// zum Abbruch: eine kaputte Datei wird zu "<Datei>.defekt" umbenannt (nicht geloescht).
func (s *server) loadStore() {
	path := s.opt.DataFile
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return // noch keine Datei = nichts zu laden
	}
	var f storeFile
	var data []byte
	if info.Size() <= maxStoreBytes {
		data, err = os.ReadFile(path)
	}
	if info.Size() > maxStoreBytes || err != nil || json.Unmarshal(data, &f) != nil || f.Version != storeVersion {
		log.Printf("Gespeicherte Eingaben unlesbar - Datei wird zu .defekt umbenannt: %s", path)
		_ = os.Rename(path, path+".defekt")
		return
	}
	n := 0
	for ip, e := range f.Entries {
		if n++; n > maxStoreEntries {
			break
		}
		s.applyEntry(ip, e)
	}
	// Eigene Kategorien: nur gueltige, ohne Doppelte, begrenzt.
	for _, k := range f.Custom {
		if model.IsCustom(k) && model.ValidCategory(k) && !s.hasCustomLocked(k) && len(s.customCats) < model.MaxCustomCategories {
			s.customCats = append(s.customCats, k)
		}
	}
	// Geraete mit eigener Kategorie, die nicht in der Liste steht, bekommen sie wieder (Datei von Hand bearbeitet o. ae.).
	for _, c := range s.cats {
		if model.IsCustom(c) && !s.hasCustomLocked(c) && len(s.customCats) < model.MaxCustomCategories {
			s.customCats = append(s.customCats, c)
		}
	}
}

// applyEntry uebernimmt einen geprueften Eintrag in die Maps (ungueltige Teile werden verworfen).
func (s *server) applyEntry(ip string, e storeEntry) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return
	}
	if e.MAC != "" {
		s.macs[ip] = strings.ToUpper(e.MAC)
	}
	if v, err := cleanName(e.Name); err == nil && v != "" {
		s.names[ip] = v
	}
	if v, err := cleanName(e.User); err == nil && v != "" {
		s.users[ip] = v
	}
	if v, err := cleanName(e.Location); err == nil && v != "" {
		s.locs[ip] = v
	}
	if model.ValidCategory(e.Category) {
		s.cats[ip] = e.Category
	}
}

// persistLocked schreibt alle Eingaben in die Datei. Aufrufer haelt s.mu.
// Fehler werden nur protokolliert (ohne Inhalte); die Arbeit im Programm geht weiter.
func (s *server) persistLocked() {
	path := s.opt.DataFile
	if path == "" {
		return
	}
	// MAC je IP merken, solange das Geraet in der Liste steht (fuer den IP-Wechsel-Schutz).
	for _, h := range s.hosts {
		if h.MAC != "" && s.hasInputsLocked(h.IP) {
			if _, ok := s.macs[h.IP]; !ok {
				s.macs[h.IP] = strings.ToUpper(h.MAC)
			}
		}
	}
	for ip := range s.macs { // MACs ohne Eingaben vergessen
		if !s.hasInputsLocked(ip) {
			delete(s.macs, ip)
		}
	}
	f := storeFile{Version: storeVersion, Entries: map[string]storeEntry{}, Custom: s.customCats}
	add := func(ip string) {
		if _, done := f.Entries[ip]; done {
			return
		}
		f.Entries[ip] = storeEntry{MAC: s.macs[ip], Name: s.names[ip], User: s.users[ip], Location: s.locs[ip], Category: s.cats[ip]}
	}
	for _, m := range []map[string]string{s.names, s.users, s.locs, s.cats} {
		for ip := range m {
			add(ip)
		}
	}
	if err := writeStoreAtomic(path, f); err != nil {
		log.Printf("Eingaben konnten nicht gespeichert werden: %v", err)
	}
}

// hasInputsLocked: gibt es zu dieser IP irgendeine Eingabe? Aufrufer haelt s.mu.
func (s *server) hasInputsLocked(ip string) bool {
	_, a := s.names[ip]
	_, b := s.users[ip]
	_, c := s.locs[ip]
	_, d := s.cats[ip]
	return a || b || c || d
}

// inputsMatch: passt die gemerkte MAC zur aktuell gesehenen? Fehlt eine von beiden, gilt "passt".
func (s *server) inputsMatch(ip, mac string) bool {
	old := s.macs[ip]
	return old == "" || mac == "" || strings.EqualFold(old, mac)
}

// claimLocked wird vor jeder Aenderung an einer IP aufgerufen: Steckt hinter der IP inzwischen
// ein anderes Geraet (MAC weicht ab), werden die alten Eingaben verworfen, damit sie nicht
// beim neuen Geraet landen. Aufrufer haelt s.mu.
func (s *server) claimLocked(ip string) {
	for _, h := range s.hosts {
		if h.IP == ip && !s.inputsMatch(ip, h.MAC) {
			delete(s.names, ip)
			delete(s.users, ip)
			delete(s.locs, ip)
			delete(s.cats, ip)
			delete(s.macs, ip)
		}
	}
}

// clearStoreLocked loescht alle Eingaben aus dem RAM und die Datei (auf ausdruecklichen Klick des Nutzers).
func (s *server) clearStoreLocked() {
	s.names, s.users = map[string]string{}, map[string]string{}
	s.locs, s.cats, s.macs = map[string]string{}, map[string]string{}, map[string]string{}
	s.customCats = nil
	s.creds.remove("") // auch alle Zugangsdaten im RAM vergessen (I-020)
	if s.opt.DataFile != "" {
		if err := os.Remove(s.opt.DataFile); err != nil && !os.IsNotExist(err) {
			log.Printf("Eingaben-Datei konnte nicht entfernt werden: %v", err)
		}
	}
}

// writeStoreAtomic schreibt die Datei ueber eine Temp-Datei im selben Ordner.
func writeStoreAtomic(path string, f storeFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".eingaben-*.tmp") // CreateTemp legt mit 0600 an
	if err != nil {
		return err
	}
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Close()
	} else {
		_ = tmp.Close()
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}
