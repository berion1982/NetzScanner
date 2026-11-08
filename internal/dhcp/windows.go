// Package dhcp liest Adresszuweisungen (Leases) und feste Reservierungen von DHCP-Servern.
// Bisher: Windows-DHCP-Server per WinRM/PowerShell (I-056). Der FRITZ!Box-Router wird in
// internal/router abgefragt.
//
// Wie es funktioniert:
//   - Verbindung per WinRM (HTTP, Port 5985) mit NTLM-Anmeldung und Nachrichtenverschluesselung.
//     Auf Windows Server ist WinRM nach meinem Wissen ab 2012 R2 standardmaessig an
//     (nicht an einem echten Server geprueft - "Ich weiss es nicht").
//   - Auf dem Server laeuft ein reiner Lese-Befehl (Get-DhcpServerv4Scope/-Lease/-Reservation,
//     Modul "DhcpServer" der DHCP-Rolle). Es wird nichts veraendert.
//   - Die Antwort kommt als Base64-kodiertes JSON zurueck (robust gegen Umlaute/Codepages).
//
// Sicherheit: Benutzer und Passwort gehen nur an den Server, werden weder gespeichert noch
// protokolliert noch in Fehlermeldungen wiederholt. Empfehlung: ein eigener Benutzer mit
// geringen Rechten (Gruppen "DHCP-Benutzer" und "Remoteverwaltungsbenutzer") statt Domain-Admin.
package dhcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/masterzen/winrm"
)

const (
	winrmPort       = 5985
	connectTimeout  = 10 * time.Second
	maxEntries      = 5000 // Schutz vor riesigen Antworten
	maxFieldRunes   = 128
	psScriptTimeout = 60 * time.Second
)

// Entry ist eine Zeile aus dem DHCP-Server: ein aktiver Lease oder eine feste Reservierung.
type Entry struct {
	Scope    string `json:"scope"`             // Netz, z. B. 192.168.10.0
	Reserved bool   `json:"reserved"`          // true = feste Reservierung, false = Lease
	IP       string `json:"ip"`                // zugewiesene Adresse
	MAC      string `json:"mac"`               // Client-ID (MAC)
	Name     string `json:"name,omitempty"`    // Hostname bzw. Reservierungsname
	Expires  string `json:"expires,omitempty"` // Ablauf des Leases (leer bei Reservierung)
	State    string `json:"state,omitempty"`   // z. B. Active
}

// psScript liest alle IPv4-Scopes samt Leases und Reservierungen (nur lesend).
// Die Ausgabe ist Base64(UTF-8-JSON); Fehler werden als Exception gemeldet (Exitcode <> 0).
const psScript = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$rows = @()
foreach ($s in @(Get-DhcpServerv4Scope)) {
  foreach ($l in @(Get-DhcpServerv4Lease -ScopeId $s.ScopeId)) {
    $rows += [pscustomobject]@{ scope = $s.ScopeId.ToString(); reserved = $false; ip = $l.IPAddress.ToString();
      mac = [string]$l.ClientId; name = [string]$l.HostName;
      expires = $(if ($l.LeaseExpiryTime) { $l.LeaseExpiryTime.ToString('yyyy-MM-dd HH:mm') } else { '' });
      state = [string]$l.AddressState }
  }
  foreach ($r in @(Get-DhcpServerv4Reservation -ScopeId $s.ScopeId)) {
    $rows += [pscustomobject]@{ scope = $s.ScopeId.ToString(); reserved = $true; ip = $r.IPAddress.ToString();
      mac = [string]$r.ClientId; name = [string]$r.Name; expires = ''; state = 'Reservation' }
  }
}
$json = ConvertTo-Json -InputObject @($rows) -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
`

// ReadWindows verbindet sich per WinRM mit dem Server und liest Leases und Reservierungen.
// Die Fehlermeldungen enthalten bewusst weder Benutzer noch Passwort noch Rohdaten.
func ReadWindows(ctx context.Context, host, user, password string) ([]Entry, error) {
	endpoint := winrm.NewEndpoint(host, winrmPort, false, false, nil, nil, nil, connectTimeout)
	enc, err := winrm.NewEncryption("ntlm") // NTLM + verschluesselte Nachrichten (auch ueber HTTP)
	if err != nil {
		return nil, fmt.Errorf("NTLM-Verschlüsselung nicht verfügbar")
	}
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return enc }
	client, err := winrm.NewClientWithParameters(endpoint, user, password, params)
	if err != nil {
		return nil, fmt.Errorf("WinRM-Verbindung nicht möglich")
	}

	ctx, cancel := context.WithTimeout(ctx, psScriptTimeout)
	defer cancel()
	out, _, code, err := client.RunPSWithContext(ctx, psScript)
	if err != nil {
		return nil, fmt.Errorf("keine Verbindung zu WinRM (Port %d erreichbar? Anmeldung korrekt? Benutzer in „Remoteverwaltungsbenutzer“?)", winrmPort)
	}
	if code != 0 {
		return nil, fmt.Errorf("DHCP-Abfrage am Server fehlgeschlagen (DHCP-Rolle installiert? Benutzer in „DHCP-Benutzer“?)")
	}
	return ParseOutput(out)
}

// ParseOutput macht aus der Base64-JSON-Ausgabe des Skripts eine bereinigte Liste. Reine Logik.
func ParseOutput(out string) ([]Entry, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil {
		return nil, fmt.Errorf("unerwartete Antwort des Servers")
	}
	var rows []Entry
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("unerwartete Antwort des Servers")
	}
	if len(rows) > maxEntries {
		rows = rows[:maxEntries]
	}
	for i := range rows {
		rows[i].Scope = clean(rows[i].Scope)
		rows[i].IP = clean(rows[i].IP)
		rows[i].MAC = clean(rows[i].MAC)
		rows[i].Name = clean(rows[i].Name)
		rows[i].Expires = clean(rows[i].Expires)
		rows[i].State = clean(rows[i].State)
	}
	return rows, nil
}

// clean entfernt Steuerzeichen und kuerzt: Die Texte kommen vom (fremden) Server.
func clean(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	if rs := []rune(s); len(rs) > maxFieldRunes {
		s = string(rs[:maxFieldRunes])
	}
	return s
}
