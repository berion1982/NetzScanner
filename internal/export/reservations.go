package export

// Export der festen DHCP-Reservierungen (I-057) als Liste: CSV (Excel Deutsch oder Standard)
// und lesbares Markdown. Die ersten vier CSV-Spalten (Netz, IP, MAC, Name) sind bewusst
// stabil gehalten, damit die Datei spaeter wieder eingelesen werden kann.

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// Reservation ist eine feste Reservierung samt dem Namen des gescannten Geraets (falls gefunden).
type Reservation struct {
	Scope    string // Netz, z. B. 192.168.10.0
	IP       string
	MAC      string
	Name     string // Name laut DHCP-Server
	ScanName string // Name des Geraets im Scan ("" = nicht gefunden)
}

var reservationHeader = []string{"Netz", "IP", "MAC", "Name (DHCP)", "Gerät im Scan"}

// WriteReservationsCSV schreibt die Liste. excel=true: Semikolon + BOM (Excel Deutsch), sonst Komma.
// Zellen sind gegen Formel-Einschleusung geschuetzt (safeCell).
func WriteReservationsCSV(w io.Writer, rows []Reservation, excel bool) error {
	if excel {
		if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
			return err
		}
	}
	cw := csv.NewWriter(w)
	if excel {
		cw.Comma = ';'
	}
	cw.UseCRLF = true
	if err := cw.Write(reservationHeader); err != nil {
		return err
	}
	for _, r := range rows {
		if err := cw.Write([]string{safeCell(r.Scope), safeCell(r.IP), safeCell(r.MAC), safeCell(r.Name), safeCell(r.ScanName)}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteReservationsMarkdown schreibt die Liste als lesbare Markdown-Tabelle.
func WriteReservationsMarkdown(w io.Writer, rows []Reservation, m Meta) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# NetzScanner – Feste DHCP-Reservierungen\n\n- Erstellt: %s\n- Programm: %s\n- Anzahl: %d\n\n",
		m.Generated.Format("02.01.2006 15:04"), mdEscape(m.Version), len(rows))
	b.WriteString("| " + strings.Join(reservationHeader, " | ") + " |\n|---|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", mdEscape(r.Scope), mdEscape(r.IP), mdEscape(r.MAC), mdEscape(r.Name), mdEscape(r.ScanName))
	}
	b.WriteString("\nHinweis: Angaben laut DHCP-Server; „Gerät im Scan“ nur, wenn die MAC beim Scan gefunden wurde.\n")
	_, err := io.WriteString(w, b.String())
	return err
}
