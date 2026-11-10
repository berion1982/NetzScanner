// Kommandozeilen-Modus ohne Browser (I-047):
//
//	netzscanner --scan 192.168.1.0/24 --out kunde.csv
//
// Der Modus startet KEINEN Webserver. Er scannt, schreibt das Ergebnis in eine Datei
// (oder nach stdout) und beendet sich. Er ist nur lesend und gibt dieselben Grenzen
// wie die Oberflaeche vor (oeffentliche Adressen nur mit --allow-public).
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/berion1982/netzscanner/internal/export"
	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/scan"
	"github.com/berion1982/netzscanner/internal/version"
)

// cliOptions bündelt die Eingaben des Kommandozeilen-Modus.
type cliOptions struct {
	Target      string // Scan-Ziel, z. B. "192.168.1.0/24" oder "10.0.0.1-10.0.0.50"
	Ports       string // Portliste wie in der Oberflaeche; leer = Standardports
	Out         string // Ausgabedatei; "-" oder leer = stdout (dann CSV)
	Format      string // csv | csv-excel | md | html | pdf; leer = aus Dateiendung
	AllowPublic bool   // auch oeffentliche Adressen scannen
}

// formatFromName leitet das Ausgabeformat aus der Dateiendung ab.
// Unbekannte Endungen und stdout ergeben CSV.
func formatFromName(out string) string {
	switch strings.ToLower(filepath.Ext(out)) {
	case ".md":
		return "md"
	case ".html", ".htm":
		return "html"
	case ".pdf":
		return "pdf"
	default:
		return "csv"
	}
}

// renderHosts schreibt die Geraeteliste im gewuenschten Format nach w.
// Es werden dieselben Export-Funktionen wie in der Oberflaeche benutzt.
func renderHosts(w io.Writer, format string, hosts []model.Host, meta export.Meta) error {
	switch format {
	case "csv":
		return export.WriteCSV(w, hosts, false)
	case "csv-excel":
		return export.WriteCSV(w, hosts, true)
	case "md":
		return export.WriteMarkdown(w, hosts, meta)
	case "html":
		return export.WriteHTML(w, hosts, meta)
	case "pdf":
		return export.WritePDF(w, hosts, meta)
	}
	return fmt.Errorf("unbekanntes Format %q (erlaubt: csv, csv-excel, md, html, pdf)", format)
}

// runCLIScan fuehrt den Scan aus und schreibt das Ergebnis. Fortschritt und Meldungen
// gehen nach logw (stderr), damit stdout nur die Daten enthaelt und in Skripten
// weiterverarbeitet werden kann. Rueckgabe: Fehler fuer Exit-Code != 0.
func runCLIScan(ctx context.Context, opt cliOptions, stdout, logw io.Writer) error {
	format := opt.Format
	if format == "" {
		format = formatFromName(opt.Out)
	}
	toStdout := opt.Out == "" || opt.Out == "-"
	if toStdout && format == "pdf" {
		return fmt.Errorf("PDF kann nicht nach stdout geschrieben werden: bitte --out <datei.pdf> angeben")
	}

	ports, err := scan.ParsePorts(opt.Ports)
	if err != nil {
		return err
	}
	// Ziel vorab pruefen, damit ein Tippfehler sofort und nicht erst nach dem Scan auffaellt.
	ips, err := scan.ExpandTarget(opt.Target, opt.AllowPublic)
	if err != nil {
		return err
	}
	fmt.Fprintf(logw, "Scanne %s (%d Adressen) ...\n", opt.Target, len(ips))

	lastPct := -1
	hosts, err := scan.Run(ctx, scan.Options{Target: opt.Target, Ports: ports, AllowPublic: opt.AllowPublic},
		func(done, total int) {
			// Fortschritt nur bei vollen 10 %-Schritten melden, damit das Log kurz bleibt.
			if total == 0 {
				return
			}
			if pct := done * 100 / total / 10 * 10; pct != lastPct {
				lastPct = pct
				fmt.Fprintf(logw, "  %d %% (%d/%d)\n", pct, done, total)
			}
		})
	if err != nil {
		return fmt.Errorf("Scan abgebrochen: %w", err)
	}
	scan.MarkSharedMAC(hosts) // gleiche MAC bei mehreren IPs: nur Hinweis, nichts ausblenden
	fmt.Fprintf(logw, "%d Geraete gefunden.\n", len(hosts))

	meta := export.Meta{Target: opt.Target, Generated: time.Now(), Version: version.String(), NetLines: scan.LocalNetInfo().Lines()}
	var buf bytes.Buffer
	if err := renderHosts(&buf, format, hosts, meta); err != nil {
		return err
	}
	if toStdout {
		_, err = stdout.Write(buf.Bytes())
		return err
	}
	// 0600: Die Datei enthaelt Netzdaten des Kunden, nicht fuer andere Benutzer lesbar.
	if err := os.WriteFile(opt.Out, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("Datei schreiben: %w", err)
	}
	fmt.Fprintf(logw, "Geschrieben: %s (%s)\n", opt.Out, format)
	return nil
}
