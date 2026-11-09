// Package findings erzeugt aus den vorhandenen Scan-Daten eine Befundliste (I-064).
//
// Grundsaetze:
//   - Es wird KEIN zusaetzlicher Netzverkehr erzeugt: ausgewertet werden nur Daten, die der
//     Scan ohnehin gesammelt hat (offene Ports, Zertifikate, gleiche MAC).
//   - Die Regeln sind allgemein (Port/Dienst/Zertifikat), es gibt keine Tabellen für einzelne
//     Geraete oder Hersteller.
//   - Ein Befund ist ein HINWEIS zum Gegenprüfen, keine bewiesene Schwachstelle: Eine
//     Portnummer verraet nur den üblichen Dienst, nicht, ob er wirklich ungeschuetzt ist.
package findings

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/berion1982/netzscanner/internal/model"
)

// Schweregrade (Reihenfolge: wichtigster zuerst).
const (
	High   = "high"   // sollte geprueft werden (z. B. unverschlüsselter Fernzugriff)
	Medium = "medium" // Dienst im Netz erreichbar, der meist nicht jeder erreichen soll
	Low    = "low"    // Schwaechere Hinweise
	Info   = "info"   // reine Information
)

// SeverityLabel liefert die deutsche Bezeichnung eines Schweregrads.
func SeverityLabel(s string) string {
	switch s {
	case High:
		return "Hoch"
	case Medium:
		return "Mittel"
	case Low:
		return "Niedrig"
	}
	return "Info"
}

// severityRank sortiert Hoch vor Mittel vor Niedrig vor Info.
func severityRank(s string) int {
	switch s {
	case High:
		return 0
	case Medium:
		return 1
	case Low:
		return 2
	}
	return 3
}

// Finding ist ein einzelner Befund zu einem Geraet.
type Finding struct {
	Severity string `json:"severity"`       // High, Medium, Low oder Info
	Rule     string `json:"rule"`           // stabile Regel-Kennung, z. B. "telnet"
	IP       string `json:"ip"`             // betroffenes Geraet
	Name     string `json:"name"`           // Geraetename zur Orientierung
	Port     int    `json:"port,omitempty"` // betroffener Port (0 = nicht portbezogen)
	Title    string `json:"title"`          // Kurzfassung
	Detail   string `json:"detail"`         // Erklaerung / Empfehlung (als Hinweis formuliert)
}

// portRule beschreibt eine Regel "Port X offen -> Hinweis".
type portRule struct {
	Port     int
	Rule     string
	Severity string
	Title    string
	Detail   string
}

// portRules sind die allgemeinen Port-Regeln. Sie gelten für jedes Geraet gleich.
var portRules = []portRule{
	{23, "telnet", High, "Telnet erreichbar",
		"Telnet überträgt Anmeldung und Daten unverschlüsselt. Wenn möglich abschalten und SSH nutzen."},
	{21, "ftp", Medium, "FTP erreichbar",
		"FTP überträgt Anmeldung und Daten meist unverschlüsselt. Prüfen, ob der Dienst gebraucht wird; sonst SFTP/FTPS nutzen."},
	{3389, "rdp", Medium, "Remote Desktop (RDP) erreichbar",
		"RDP gilt als häufiges Angriffsziel. Prüfen, ob der Zugriff nur aus dem Verwaltungsnetz möglich sein soll."},
	{5900, "vnc", Medium, "VNC (Fernsteuerung) erreichbar",
		"VNC ist oft schwach oder gar nicht abgesichert. Prüfen, ob Passwort/Verschlüsselung aktiv sind."},
	{445, "smb", Medium, "Dateifreigabe (SMB) erreichbar",
		"SMB ist im lokalen Netz üblich. Prüfen, ob Freigaben und Anmeldung wie gewollt eingerichtet sind."},
	{139, "netbios-ssn", Low, "NetBIOS-Sitzungsdienst (139) erreichbar",
		"Älterer Windows-Dateidienst. Prüfen, ob er noch gebraucht wird."},
	{5985, "winrm-http", Low, "WinRM ueber HTTP (5985) erreichbar",
		"Windows-Fernverwaltung. Prüfen, ob der Zugriff beschränkt ist; HTTPS (5986) ist vorzuziehen."},
	{1883, "mqtt", Low, "MQTT ohne Verschlüsselung (1883) erreichbar",
		"Nachrichten und Anmeldung könnten im Klartext laufen. Prüfen, ob eine Anmeldung verlangt wird bzw. 8883 (TLS) möglich ist."},
	{111, "rpcbind", Low, "rpcbind (111) erreichbar",
		"Dienst-Verzeichnis für NFS u. Ä. Prüfen, ob er im Netz erreichbar sein muss."},
	{3306, "db-mysql", Medium, "Datenbank erreichbar: MySQL/MariaDB (3306)",
		"Datenbanken sollten meist nur für die Anwendung erreichbar sein. Zugriffsbeschränkung prüfen."},
	{5432, "db-postgres", Medium, "Datenbank erreichbar: PostgreSQL (5432)",
		"Datenbanken sollten meist nur für die Anwendung erreichbar sein. Zugriffsbeschränkung prüfen."},
	{1433, "db-mssql", Medium, "Datenbank erreichbar: Microsoft SQL Server (1433)",
		"Datenbanken sollten meist nur für die Anwendung erreichbar sein. Zugriffsbeschränkung prüfen."},
	{1521, "db-oracle", Medium, "Datenbank erreichbar: Oracle (1521)",
		"Datenbanken sollten meist nur für die Anwendung erreichbar sein. Zugriffsbeschränkung prüfen."},
	{27017, "db-mongodb", Medium, "Datenbank erreichbar: MongoDB (27017)",
		"Ältere Installationen laufen ohne Anmeldung. Zugriffsschutz prüfen."},
	{6379, "cache-redis", Medium, "Cache erreichbar: Redis (6379)",
		"Redis hat standardmäßig oft keine Anmeldung. Zugriffsschutz prüfen."},
	{9200, "search-elasticsearch", Medium, "Suchdienst erreichbar: Elasticsearch (9200)",
		"Der Dienst hat je nach Einrichtung keine Anmeldung. Zugriffsschutz prüfen."},
}

// Web-Ports: unverschlüsselt (HTTP) und verschlüsselt (HTTPS).
var (
	httpPorts  = []int{80, 8000, 8080, 8081, 5000, 8888}
	httpsPorts = []int{443, 8443, 5001}
)

// expiringDays: Zertifikate, die in weniger Tagen ablaufen, gelten als "läuft bald ab".
// Gleicher Wert wie im Detail-Panel der Oberflaeche.
const expiringDays = 30

// Analyze wertet alle Geraete aus und liefert die Befunde, sortiert nach Schweregrad,
// dann Regel, dann IP. Laeuft der Scan noch (Pending), sind die Ports evtl. unvollstaendig;
// die Befunde sind dann ebenfalls vorlaeufig.
func Analyze(hosts []model.Host) []Finding {
	out := []Finding{}
	for _, h := range hosts {
		out = append(out, analyzeHost(h)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return ipBefore(a.IP, b.IP)
	})
	return out
}

// analyzeHost wendet alle Regeln auf ein Geraet an.
func analyzeHost(h model.Host) []Finding {
	var out []Finding
	add := func(sev, rule string, port int, title, detail string) {
		out = append(out, Finding{Severity: sev, Rule: rule, IP: h.IP, Name: h.Name, Port: port, Title: title, Detail: detail})
	}
	open := map[int]model.Port{}
	for _, p := range h.Ports {
		open[p.Number] = p
	}
	// 1. Port-Regeln (Telnet, FTP, RDP, Datenbanken ...)
	for _, r := range portRules {
		if _, ok := open[r.Port]; ok {
			add(r.Severity, r.Rule, r.Port, r.Title, r.Detail)
		}
	}
	// 2. Zertifikate (nur gelesen, nicht geprueft)
	for _, p := range h.Ports {
		if p.Cert == nil {
			continue
		}
		switch {
		case p.Cert.Expired:
			add(Medium, "cert-expired", p.Number, fmt.Sprintf("Zertifikat abgelaufen (Port %d)", p.Number),
				fmt.Sprintf("Das TLS-Zertifikat lief am %s ab. Browser warnen dann; Zertifikat erneuern.", p.Cert.NotAfter))
		case p.Cert.DaysLeft < expiringDays:
			add(Low, "cert-expiring", p.Number, fmt.Sprintf("Zertifikat läuft bald ab (Port %d)", p.Number),
				fmt.Sprintf("Das TLS-Zertifikat läuft am %s ab (in %d Tagen). Rechtzeitig erneuern.", p.Cert.NotAfter, p.Cert.DaysLeft))
		}
	}
	// 3. Weboberfläche nur per HTTP: HTTP-Port offen, aber kein HTTPS-Port.
	if hasAny(open, httpPorts) && !hasAny(open, httpsPorts) {
		add(Info, "http-only", firstOpen(open, httpPorts), "Weboberfläche nur per HTTP",
			"Es wurde kein HTTPS-Port gefunden. Eine Anmeldung auf der Weboberfläche läuft dann unverschlüsselt. Prüfen, ob HTTPS am Geraet verfuegbar ist.")
	}
	// 4. Gleiche MAC bei mehreren IPs (siehe scan.MarkSharedMAC)
	if len(h.SameMAC) > 0 {
		add(Info, "same-mac", 0, "Gleiche MAC bei mehreren IP-Adressen",
			fmt.Sprintf("Dieselbe MAC-Adresse hat auch: %s. Oft ein Scheineintrag (Router antwortet für fremde Adressen) oder ein Geraet mit mehreren Adressen. Im Router gegenprüfen.", join(h.SameMAC)))
	}
	return out
}

// hasAny sagt, ob mindestens einer der Ports offen ist.
func hasAny(open map[int]model.Port, ports []int) bool { return firstOpen(open, ports) != 0 }

// firstOpen liefert den ersten offenen Port der Liste (0 = keiner).
func firstOpen(open map[int]model.Port, ports []int) int {
	for _, p := range ports {
		if _, ok := open[p]; ok {
			return p
		}
	}
	return 0
}

// join verbindet IPs mit ", ".
func join(s []string) string {
	r := ""
	for i, v := range s {
		if i > 0 {
			r += ", "
		}
		r += v
	}
	return r
}

// ipBefore vergleicht IPs numerisch ("10.0.0.9" vor "10.0.0.10"); Unlesbares nach Text.
func ipBefore(a, b string) bool {
	x, ea := netip.ParseAddr(a)
	y, eb := netip.ParseAddr(b)
	if ea != nil || eb != nil {
		return a < b
	}
	return x.Compare(y) < 0
}
