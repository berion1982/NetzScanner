// Package export erzeugt Dateien aus der (vom Nutzer ausgewaehlten) Geraeteliste:
// CSV zum Weiterverarbeiten und lesbare Tabellen (HTML, Markdown).
//
// WICHTIG: Passwoerter gehoeren NIE in einen Export. Dieses Paket kennt gar keine
// Passwort-Felder - das Datenmodell enthaelt keine.
package export

import (
	"encoding/csv"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
)

// Meta beschreibt, woher eine lesbare Tabelle stammt (steht im Kopf der Datei).
type Meta struct {
	Target    string    // gescanntes Ziel, z.B. "192.168.178.0/24"
	Generated time.Time // Erzeugungszeitpunkt
	Version   string    // Programmversion, z.B. "NetzScanner 0.4.0 (...)"
}

// csvHeader sind die Spalten der CSV, in der vom Nutzer festgelegten Reihenfolge.
var csvHeader = []string{"Benutzername", "IP", "MAC", "Gerätename", "Offene Ports"}

// portList liefert die Portnummern als "22, 80, 443".
func portList(h model.Host) string {
	parts := make([]string, len(h.Ports))
	for i, p := range h.Ports {
		parts[i] = strconv.Itoa(p.Number)
	}
	return strings.Join(parts, ", ")
}

// safeCell entschaerft Zellen gegen "CSV-Injection": Beginnt ein Text mit = + - @
// (oder Tab/Zeilenumbruch), wuerde Excel/LibreOffice ihn als Formel ausfuehren.
// Gerätenamen kommen aus dem Netz und sind nicht vertrauenswuerdig. Ein vorangestelltes
// Hochkomma macht daraus normalen Text.
func safeCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r\n", rune(s[0])) {
		return "'" + s
	}
	return s
}

// WriteCSV schreibt die Geraete als CSV: Benutzername, IP, MAC, Gerätename, Offene Ports.
//
// excelDE=true: Semikolon als Trennzeichen und UTF-8-BOM, damit deutsches Excel Umlaute
// und Spalten richtig erkennt. false: Standard-CSV mit Komma ohne BOM (fuer andere Programme).
func WriteCSV(w io.Writer, hosts []model.Host, excelDE bool) error {
	if excelDE {
		if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil { // UTF-8-BOM
			return err
		}
	}
	cw := csv.NewWriter(w)
	cw.UseCRLF = true
	if excelDE {
		cw.Comma = ';'
	}
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, h := range hosts {
		row := []string{safeCell(h.Username), safeCell(h.IP), safeCell(h.MAC), safeCell(h.Name), portList(h)}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// mdEscape schuetzt Markdown-Sonderzeichen in Zellen (Namen kommen aus dem Netz).
func mdEscape(s string) string {
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	for _, c := range []string{`\`, "|", "`", "*", "_", "[", "]"} {
		s = strings.ReplaceAll(s, c, `\`+c)
	}
	if s == "" {
		return "–"
	}
	return s
}

// WriteMarkdown schreibt eine lesbare Tabelle als Markdown.
func WriteMarkdown(w io.Writer, hosts []model.Host, m Meta) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# NetzScanner – Geräteliste\n\n")
	fmt.Fprintf(&b, "- Ziel: %s\n- Erstellt: %s\n- Programm: %s\n- Geräte: %d\n\n",
		mdEscape(m.Target), m.Generated.Format("02.01.2006 15:04"), mdEscape(m.Version), len(hosts))
	b.WriteString("| Name | IP | MAC | Hersteller | Benutzername | Offene Ports |\n|---|---|---|---|---|---|\n")
	for _, h := range hosts {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", mdEscape(h.Name), mdEscape(h.IP), mdEscape(h.MAC),
			mdEscape(h.Vendor), mdEscape(h.Username), mdEscape(portList(h)))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// htmlPage ist die lesbare Tabelle als eigenstaendige Datei (hell zum Drucken,
// dunkel bei dunklem Browser-Thema). html/template maskiert alle Werte automatisch.
var htmlPage = template.Must(template.New("t").Parse(`<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetzScanner – Geräteliste</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;margin:24px;background:#fff;color:#1f2328}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #d0d7de;padding:6px 10px;text-align:left;vertical-align:top}
th{background:#f6f8fa}.meta{color:#57606a;margin-bottom:16px}a{color:#0969da}
@media(prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}th{background:#161b22}th,td{border-color:#30363d}.meta{color:#9da7b3}a{color:#58a6ff}}
</style></head><body>
<h1>NetzScanner – Geräteliste</h1>
<div class="meta">Ziel: {{.Meta.Target}} · Erstellt: {{.Generated}} · {{.Meta.Version}} · {{len .Hosts}} Geräte</div>
<table><thead><tr><th>Name</th><th>IP</th><th>MAC</th><th>Hersteller</th><th>Benutzername</th><th>Offene Ports</th><th>Web</th></tr></thead><tbody>
{{range .Hosts}}<tr><td>{{.Name}}</td><td>{{.IP}}</td><td>{{.MAC}}</td><td>{{.Vendor}}</td><td>{{.Username}}</td><td>{{range $i, $p := .Ports}}{{if $i}}, {{end}}{{$p.Number}}{{if $p.Service}} ({{$p.Service}}){{end}}{{end}}</td><td>{{range .WebLinks}}<a href="{{.URL}}" rel="noopener noreferrer">{{.Label}}</a> {{end}}</td></tr>
{{end}}</tbody></table></body></html>
`))

// WriteHTML schreibt die lesbare Tabelle als HTML-Datei.
func WriteHTML(w io.Writer, hosts []model.Host, m Meta) error {
	return htmlPage.Execute(w, struct {
		Meta      Meta
		Hosts     []model.Host
		Generated string
	}{m, hosts, m.Generated.Format("02.01.2006 15:04")})
}
