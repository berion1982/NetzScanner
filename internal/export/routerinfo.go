package export

// Export der Router-Daten (I-055) als eigene Datei: lesbares Markdown und CSV der WLANs.
//
// Bewusst NICHT enthalten: externe IP-Adresse, Seriennummer, WLAN-Schluessel, Zugangsdaten
// (die werden gar nicht gelesen bzw. nicht in die Daten uebernommen). Texte stammen vom
// Router und werden wie alle Fremdtexte maskiert (Markdown) bzw. gegen Formeln gesichert (CSV).

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/berion1982/netzscanner/internal/router"
)

// durationText macht aus Sekunden "3 Tage 4 Std 5 Min" (leer bei 0).
func durationText(sec int64) string {
	if sec <= 0 {
		return ""
	}
	d, h, m := sec/86400, sec%86400/3600, sec%3600/60
	var parts []string
	if d > 0 {
		parts = append(parts, fmt.Sprintf("%d Tage", d))
	}
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%d Std", h))
	}
	if m > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d Min", m))
	}
	return strings.Join(parts, " ")
}

// WriteRouterMarkdown schreibt Router-Info, WLAN-Netze und WLAN-Clients als Markdown.
func WriteRouterMarkdown(w io.Writer, info router.Info, m Meta) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# NetzScanner – Router und WLAN\n\n- Erstellt: %s\n- Programm: %s\n\n", m.Generated.Format("02.01.2006 15:04"), mdEscape(m.Version))
	b.WriteString("## Router\n\n")
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "- %s: %s\n", k, mdEscape(v))
		}
	}
	row("Modell", info.Model)
	row("Firmware", info.Firmware)
	row("Laufzeit", durationText(info.UptimeSec))
	row("Internet", info.WANStatus)
	row("Anschluss", info.WANAccess)
	if info.DownKbps > 0 || info.UpKbps > 0 {
		row("Leitungsrate (max.)", fmt.Sprintf("%d / %d Mbit/s (Down/Up)", info.DownKbps/1000, info.UpKbps/1000))
	}
	if info.DHCPEnabled {
		row("DHCP-Bereich", info.DHCPFrom+" – "+info.DHCPTo)
	}
	row("Netzmaske", info.Subnet)
	row("Gateway", info.Gateway)
	row("DNS", info.DNS)
	b.WriteString("\n## WLAN-Netze\n\n| Nr. | Name (SSID) | Aktiv | Band | Kanal | Standard | Verschlüsselung | Clients |\n|---|---|---|---|---|---|---|---|\n")
	for _, wl := range info.WLANs {
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %s | %d |\n", wl.Index, mdEscape(wl.SSID), yesNo(wl.Enabled), mdEscape(wl.Band),
			chanText(wl.Channel), mdEscape(wl.Standard), mdEscape(wl.Encryption), len(wl.Clients))
	}
	b.WriteString("\n## WLAN-Clients\n\n| WLAN | MAC | IP | Signal | Geschwindigkeit |\n|---|---|---|---|---|\n")
	for _, wl := range info.WLANs {
		for _, c := range wl.Clients {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", mdEscape(wl.SSID), mdEscape(c.MAC), mdEscape(c.IP), pctText(c.Signal), mbitText(c.Speed))
		}
	}
	if len(info.Notes) > 0 {
		b.WriteString("\n## Nicht gelesen\n\n")
		for _, n := range info.Notes {
			fmt.Fprintf(&b, "- %s\n", mdEscape(n))
		}
	}
	b.WriteString("\nHinweis: Angaben laut Router (TR-064); die WLAN-Schlüssel und die externe IP sind bewusst nicht enthalten.\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// WriteRouterCSV schreibt die WLAN-Netze (eine Zeile je WLAN), Excel-freundlich mit Semikolon und BOM.
func WriteRouterCSV(w io.Writer, info router.Info) error {
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	cw.UseCRLF = true
	if err := cw.Write([]string{"Nr.", "Name (SSID)", "Aktiv", "Band", "Kanal", "Standard", "Verschlüsselung", "Clients"}); err != nil {
		return err
	}
	for _, wl := range info.WLANs {
		if err := cw.Write([]string{strconv.Itoa(wl.Index), safeCell(wl.SSID), yesNo(wl.Enabled), safeCell(wl.Band), plain(chanText(wl.Channel)),
			safeCell(wl.Standard), safeCell(wl.Encryption), strconv.Itoa(len(wl.Clients))}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func yesNo(b bool) string {
	if b {
		return "ja"
	}
	return "nein"
}

func chanText(ch int) string {
	if ch <= 0 {
		return "–"
	}
	return strconv.Itoa(ch)
}

func plain(s string) string { return strings.TrimSpace(s) }

func pctText(p int) string {
	if p <= 0 {
		return "–"
	}
	return strconv.Itoa(p) + " %"
}

func mbitText(s int) string {
	if s <= 0 {
		return "–"
	}
	return strconv.Itoa(s) + " Mbit/s"
}
