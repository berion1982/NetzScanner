package export

import (
	"fmt"
	"github.com/berion1982/netzscanner/internal/model"
	"html"
	"io"
	"strings"
)

// BookmarkCount zaehlt die Web-Links, die in eine Lesezeichen-Datei kaemen.
func BookmarkCount(hosts []model.Host) int {
	n := 0
	for _, h := range hosts {
		n += len(h.WebLinks)
	}
	return n
}

// bookmarkTitle baut den sichtbaren Titel: "Gerätename (IP) – https :443".
// Der Name kommt aus dem Netz und wird deshalb HTML-maskiert.
func bookmarkTitle(name, ip, label string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == ip {
		return html.EscapeString(fmt.Sprintf("%s – %s", ip, label))
	}
	return html.EscapeString(fmt.Sprintf("%s (%s) – %s", name, ip, label))
}

// WriteBookmarks schreibt eine Lesezeichen-Datei im Netscape-Format
// (wird von Firefox und Chrome/Edge importiert).
//
// toolbar=true markiert den Ordner "NetzScanner" mit PERSONAL_TOOLBAR_FOLDER,
// damit er als Lesezeichenleiste erkannt wird. UNBESTAETIGT: ob das in beiden
// Browsern greift - Fallback ist toolbar=false (normaler Ordner "NetzScanner").
// Es werden nur die URLs aus FillWebLinks geschrieben (aus validierter IP gebaut),
// niemals Zugangsdaten.
func WriteBookmarks(w io.Writer, hosts []model.Host, m Meta, toolbar bool) error {
	ts := m.Generated.Unix() // ADD_DATE erwartet Unix-Sekunden
	attr := ""
	if toolbar {
		attr = ` PERSONAL_TOOLBAR_FOLDER="true"`
	}
	var b strings.Builder
	b.WriteString("<!DOCTYPE NETSCAPE-Bookmark-file-1>\n")
	b.WriteString("<!-- Erzeugt von " + html.EscapeString(m.Version) + " -->\n")
	b.WriteString("<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n")
	b.WriteString("<TITLE>Bookmarks</TITLE>\n<H1>Bookmarks</H1>\n<DL><p>\n")
	fmt.Fprintf(&b, "    <DT><H3 ADD_DATE=\"%d\" LAST_MODIFIED=\"%d\"%s>NetzScanner</H3>\n    <DL><p>\n", ts, ts, attr)
	for _, h := range hosts {
		for _, l := range h.WebLinks {
			fmt.Fprintf(&b, "        <DT><A HREF=\"%s\" ADD_DATE=\"%d\">%s</A>\n",
				html.EscapeString(l.URL), ts, bookmarkTitle(h.Name, h.IP, l.Label))
		}
	}
	b.WriteString("    </DL><p>\n</DL><p>\n")
	_, err := io.WriteString(w, b.String())
	return err
}
