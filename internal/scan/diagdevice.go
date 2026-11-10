package scan

// diagdevice.go – Diagnose-Bericht fuer EIN Geraet (I-074).
//
// Der Bericht sammelt das Maximum an Informationen zu einem einzelnen Geraet und gibt es als
// Text aus (zum Kopieren/Speichern und Weitergeben bei der Fehlersuche):
//
//	A) alles, was der Scan und die Eingaben schon wissen (gespeicherte Daten, ohne neuen Verkehr);
//	B) die aktiven Pruefschritte aus Diagnose() (DNS, Ports, ARP, Reverse-DNS, TLS, Web, Namenssuche);
//	C) auf ausdruecklichen Wunsch zusaetzlich: Ping, Traceroute, voller Portscan (1-65535).
//
// Regeln:
//   - nur lesend; es wird nichts im Netz oder auf dem Geraet veraendert;
//   - ping/traceroute laufen ueber die Systembefehle (feste Argumente, KEINE Shell, IP vorher als
//     IPv4 geprueft). Die Systemprogramme sind meist so eingerichtet, dass sie auch ohne
//     Root-/Administratorrechte laufen; braucht einer doch Rechte, steht ein Hinweis im Bericht
//     (NetzScanner startet sich nicht selbst mit hoeheren Rechten). Ohne Ping-Befehl gibt es als
//     Ersatz eine Laufzeitmessung per TCP-Verbindungsaufbau;
//   - jeder Baustein hat eine eigene Frist; ein Fehler bricht den Bericht nicht ab;
//   - keine Zugangsdaten im Bericht (die Daten des Geraets enthalten keine).

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/version"
)

// DiagOptions waehlt die optionalen, aktiven Bausteine des Berichts.
type DiagOptions struct {
	Ping      bool // Ping (4x) bzw. TCP-Laufzeitmessung als Ersatz
	Trace     bool // Traceroute (Weg zum Geraet)
	FullPorts bool // voller Portscan 1-65535 nur dieses Geraets (kann mehrere Minuten dauern)
}

// Fristen der einzelnen Bausteine.
const (
	diagPingTimeout  = 25 * time.Second
	diagTraceTimeout = 90 * time.Second
	diagFullTimeout  = 10 * time.Minute
	diagCmdMaxBytes  = 32 * 1024 // mehr Ausgabe eines Systembefehls wird abgeschnitten
)

// DiagnoseDevice schreibt den kompletten Bericht zu einem Geraet in w.
// extra sind zusaetzliche, schon fertige Zeilen (z. B. Login-Test-Ergebnisse ohne Passwort),
// die unter "Login-Tests" erscheinen. Die IP des Geraets muss eine gueltige IP sein.
func DiagnoseDevice(ctx context.Context, h model.Host, opts DiagOptions, extra []string, w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("== NetzScanner Geräte-Diagnose ==")
	p("Version: %s", version.String())
	p("Zeit:    %s", time.Now().Format("2006-01-02 15:04:05 MST"))
	p("System:  %s/%s", runtime.GOOS, runtime.GOARCH)
	p("Ziel:    %s", h.IP)
	addr, err := netip.ParseAddr(h.IP)
	if err != nil {
		p("FEHLER: keine gueltige IP-Adresse")
		return
	}

	p("\n=== A) Gespeicherte Daten (kein neuer Netzverkehr) ===")
	for _, l := range storedHostLines(h) {
		p("%s", l)
	}
	if len(extra) > 0 {
		p("\nLogin-Tests (nur Ergebnis, ohne Zugangsdaten):")
		for _, l := range extra {
			p("    %s", l)
		}
	}
	p("\nNetz dieses Rechners:")
	for _, kv := range LocalNetInfo().Lines() {
		p("    %-22s %s", kv[0], kv[1])
	}

	p("\n=== B) Aktive Pruefungen ===")
	diagChecks(ctx, p, h.IP)

	if !opts.Ping && !opts.Trace && !opts.FullPorts {
		return
	}
	p("\n=== C) Zusatzbausteine ===")
	if !addr.Is4() {
		p("    Ping/Traceroute sind nur fuer IPv4 vorgesehen; uebersprungen.")
	}
	if opts.Ping && addr.Is4() {
		p("\n[8] Ping")
		diagPing(ctx, p, h, addr)
	}
	if opts.Trace && addr.Is4() {
		p("\n[9] Traceroute (Weg zum Geraet)")
		diagTrace(ctx, p, addr)
	}
	if opts.FullPorts {
		p("\n[10] Voller Portscan 1-65535 (nur dieses Geraet)")
		diagFullPorts(ctx, p, addr)
	}
	p("\n== Ende des Berichts ==")
}

// storedHostLines beschreibt alles, was zu dem Geraet schon gespeichert ist, als Textzeilen.
// Reine Logik, ohne Netzwerk testbar. Das Host-Modell enthaelt keine Zugangsdaten.
func storedHostLines(h model.Host) []string {
	var out []string
	add := func(name, value string) {
		if strings.TrimSpace(value) != "" {
			out = append(out, fmt.Sprintf("    %-22s %s", name+":", value))
		}
	}
	add("Name", h.Name)
	add("Namensquelle", h.NameSource)
	add("Urspruenglicher Name", h.ScannedName)
	add("Name laut Router", h.RouterName)
	add("MAC", h.MAC)
	add("Hersteller (OUI)", h.Vendor)
	add("System (Vermutung)", h.OS)
	cat := h.Category
	if h.CategoryManual {
		cat += " (vom Nutzer gewaehlt)"
	} else {
		cat += " (Vermutung des Scans)"
	}
	add("Kategorie", cat)
	add("Rolle", h.Role)
	add("Standort", h.Location)
	add("Benutzername (Anzeige)", h.Username)
	add("Uplink", h.Uplink)
	add("Anschluss am Uplink", h.UplinkPort)
	if h.UplinkShared > 0 {
		add("MACs an diesem Port", strconv.Itoa(h.UplinkShared))
	}
	add("Mesh-Verbindung", h.MeshLink)
	add("Verbindung (Router)", h.Connection)
	if h.WifiSSID != "" {
		add("WLAN (Router)", fmt.Sprintf("%s, Signal %d %%, %d Mbit/s", h.WifiSSID, h.WifiSignal, h.WifiSpeed))
	}
	add("DHCP", h.DHCP)
	add("Gleiche MAC wie", strings.Join(h.SameMAC, ", "))
	add("Scheineintrag von", h.MirrorOf)
	for _, f := range h.SysInfo {
		add("Info: "+f.Name, f.Value)
	}
	if len(h.Ports) == 0 {
		out = append(out, "    Offene Ports:          keine gefunden")
	}
	for _, pt := range h.Ports {
		line := fmt.Sprintf("    Port %-5d %-12s", pt.Number, pt.Service)
		if pt.Banner != "" {
			line += fmt.Sprintf(" banner=%q", pt.Banner)
		}
		if c := pt.Cert; c != nil {
			line += fmt.Sprintf(" zertifikat=[%s | von %s | bis %s | selbst signiert: %t | abgelaufen: %t]",
				c.Subject, c.Issuer, c.NotAfter, c.SelfSigned, c.Expired)
		}
		out = append(out, line)
	}
	return out
}

// diagCommand ist ein fester Systembefehl samt Argumenten (wird nie ueber eine Shell gestartet).
type diagCommand struct {
	name string
	args []string
}

// pingCommand baut den Ping-Befehl fuer das Betriebssystem. Die IP muss eine geprueft gueltige
// IPv4-Adresse sein (kann so nie mit "-" beginnen). Reine Logik, ohne Netzwerk testbar.
func pingCommand(goos, ip string) diagCommand {
	switch goos {
	case "windows":
		return diagCommand{"ping", []string{"-n", "4", "-w", "2000", ip}}
	case "darwin":
		return diagCommand{"ping", []string{"-n", "-c", "4", ip}}
	default: // Linux und andere: -W = Wartezeit je Antwort in Sekunden
		return diagCommand{"ping", []string{"-n", "-c", "4", "-W", "2", ip}}
	}
}

// traceCommands liefert die Traceroute-Befehle in der Reihenfolge, in der sie versucht werden
// (der erste vorhandene gewinnt). Reine Logik, ohne Netzwerk testbar.
func traceCommands(goos, ip string) []diagCommand {
	switch goos {
	case "windows":
		return []diagCommand{{"tracert", []string{"-d", "-w", "1000", "-h", "20", ip}}}
	case "darwin":
		return []diagCommand{{"traceroute", []string{"-n", "-w", "2", "-q", "1", "-m", "20", ip}}}
	default:
		// tracepath braucht keine Sonderrechte; traceroute liefert oft mehr Details.
		return []diagCommand{
			{"traceroute", []string{"-n", "-w", "2", "-q", "1", "-m", "20", ip}},
			{"tracepath", []string{"-n", "-m", "20", ip}},
		}
	}
}

// diagPing fuehrt Ping aus. Fehlt der Befehl, misst es ersatzweise die Laufzeit per TCP.
func diagPing(ctx context.Context, p func(string, ...any), h model.Host, addr netip.Addr) {
	cmd := pingCommand(runtime.GOOS, addr.String())
	if runDiagCommand(ctx, p, cmd, diagPingTimeout) {
		return
	}
	p("    Befehl %q nicht gefunden - Ersatz: Laufzeit per TCP-Verbindungsaufbau (kein ICMP).", cmd.name)
	var ports []int
	for _, pt := range h.Ports {
		if len(ports) < 3 {
			ports = append(ports, pt.Number)
		}
	}
	if len(ports) == 0 {
		ports = []int{80, 443, 22, 445}
	}
	diagTCPPing(ctx, p, addr.String(), ports)
}

// diagTrace fuehrt den ersten vorhandenen Traceroute-Befehl aus.
func diagTrace(ctx context.Context, p func(string, ...any), addr netip.Addr) {
	var names []string
	for _, cmd := range traceCommands(runtime.GOOS, addr.String()) {
		names = append(names, cmd.name)
		if runDiagCommand(ctx, p, cmd, diagTraceTimeout) {
			return
		}
	}
	p("    Kein Traceroute-Programm gefunden (gesucht: %s). Bitte installieren (z. B. Paket traceroute).", strings.Join(names, ", "))
}

// runDiagCommand startet den Befehl (falls vorhanden) und schreibt dessen Ausgabe eingerueckt
// in den Bericht. Rueckgabe false = Programm nicht gefunden (nichts ausgefuehrt).
func runDiagCommand(ctx context.Context, p func(string, ...any), c diagCommand, timeout time.Duration) bool {
	path, err := exec.LookPath(c.name)
	if err != nil {
		return false
	}
	p("    $ %s %s", c.name, strings.Join(c.args, " "))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, c.args...)
	if runtime.GOOS != "windows" {
		cmd.Env = append(os.Environ(), "LC_ALL=C") // gleichbleibende Meldungen fuer die Fehlersuche
	}
	buf := &limitedBuffer{max: diagCmdMaxBytes}
	cmd.Stdout, cmd.Stderr = buf, buf
	runErr := cmd.Run()
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\r\n"), "\n") {
		if l := sanitizeUTF8(strings.TrimRight(line, "\r")); l != "" {
			p("    %s", l)
		}
	}
	switch {
	case ctx.Err() != nil:
		p("    (abgebrochen: Zeitlimit von %s erreicht)", timeout)
	case runErr != nil:
		p("    (Befehl endete mit: %v)", runErr)
	}
	if runErr != nil && needsRightsHint(buf.String()) {
		p("    Hinweis: Dieser Befehl scheint erhoehte Rechte (root/Administrator) zu brauchen.")
		p("    NetzScanner startet sich nicht selbst mit hoeheren Rechten. Moeglich: Programm einmal")
		p("    mit sudo bzw. als Administrator starten, oder dem Systembefehl die Berechtigung geben.")
	}
	return true
}

// needsRightsHint erkennt typische Meldungen, die auf fehlende Rechte hindeuten.
// Reine Logik, ohne Netzwerk testbar.
func needsRightsHint(output string) bool {
	t := strings.ToLower(output)
	for _, k := range []string{"operation not permitted", "permission denied", "must be root", "requires root",
		"access is denied", "zugriff verweigert", "icmp open socket", "socket: permission"} {
		if strings.Contains(t, k) {
			return true
		}
	}
	return false
}

// limitedBuffer sammelt Ausgabe, hoert aber bei max Bytes auf (Schutz vor endloser Ausgabe).
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

// Write nimmt immer alles an (sonst bricht der Befehl mit einem Schreibfehler ab), speichert aber nur bis max.
func (l *limitedBuffer) Write(b []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(b) > room {
			l.buf.Write(b[:room])
		} else {
			l.buf.Write(b)
		}
	}
	return len(b), nil
}

func (l *limitedBuffer) String() string { return l.buf.String() }

// diagTCPPing misst je Port viermal die Dauer des TCP-Verbindungsaufbaus. "Abgelehnt" (RST)
// zaehlt auch: Das Geraet hat geantwortet, nur der Port ist zu.
func diagTCPPing(ctx context.Context, p func(string, ...any), ip string, ports []int) {
	for _, port := range ports {
		var times []time.Duration
		lost := 0
		for i := 0; i < 4; i++ {
			start := time.Now()
			d := net.Dialer{Timeout: 2 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			el := time.Since(start)
			if err == nil {
				conn.Close()
				times = append(times, el)
			} else if strings.Contains(strings.ToLower(err.Error()), "refused") {
				times = append(times, el)
			} else {
				lost++
			}
		}
		p("    TCP-Port %-5d %s", port, rttSummary(times, lost))
	}
}

// rttSummary fasst Laufzeiten zusammen ("4 von 4 Antworten, min/mittel/max ..."). Reine Logik.
func rttSummary(times []time.Duration, lost int) string {
	total := len(times) + lost
	if len(times) == 0 {
		return fmt.Sprintf("0 von %d Antworten", total)
	}
	min, max, sum := times[0], times[0], time.Duration(0)
	for _, t := range times {
		if t < min {
			min = t
		}
		if t > max {
			max = t
		}
		sum += t
	}
	r := func(d time.Duration) string { return d.Round(10 * time.Microsecond).String() }
	return fmt.Sprintf("%d von %d Antworten, min/mittel/max = %s / %s / %s",
		len(times), total, r(min), r(sum/time.Duration(len(times))), r(max))
}

// diagFullPorts prueft alle 65535 TCP-Ports dieses einen Geraets (mit Banner wie beim Scan) und
// markiert Ports, die nicht in der Standardliste des Scans stehen.
func diagFullPorts(ctx context.Context, p func(string, ...any), addr netip.Addr) {
	ctx, cancel := context.WithTimeout(ctx, diagFullTimeout)
	defer cancel()
	p("    laeuft - das kann je nach Geraet mehrere Minuten dauern ...")
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	start := time.Now()
	found := scanHost(ctx, addr, ports, time.Second, make(chan struct{}, 256))
	sort.Slice(found, func(i, j int) bool { return found[i].Number < found[j].Number })
	std := map[int]bool{}
	for _, n := range DefaultPorts {
		std[n] = true
	}
	if len(found) == 0 {
		p("    keine offenen Ports gefunden")
	}
	for _, pt := range found {
		mark := ""
		if !std[pt.Number] {
			mark = "  <- nicht in der Standardliste des Scans"
		}
		p("    %d (%s) banner=%q%s", pt.Number, pt.Service, pt.Banner, mark)
	}
	note := ""
	if ctx.Err() != nil {
		note = " (UNVOLLSTAENDIG: Zeitlimit/Abbruch)"
	}
	p("    fertig nach %s%s", time.Since(start).Round(time.Second), note)
}
