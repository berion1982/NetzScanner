package logintest

// WinRM-Login-Test (I-022 Rest): prueft, ob ein Windows-Rechner/Domaenencontroller die Anmeldung
// per WinRM (Port 5985, NTLM mit verschluesselten Nachrichten) akzeptiert.
//
// Ablauf: genau ein Verbindungsversuch. Beim Oeffnen der Shell wird angemeldet; danach laeuft
// ein einziger fester, rein lesender Befehl ("hostname"). Es wird nichts geschrieben.
// Das Passwort taucht in keiner Meldung auf.

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

// MethodWinRM ist der Methodenname fuer Ergebnis und Oberflaeche.
const MethodWinRM = "winrm"

// WinRMPort ist der Standard-Port fuer WinRM ueber HTTP (die Nachrichten sind per NTLM verschluesselt).
const WinRMPort = 5985

// winrmInfoCommand ist der EINZIGE Befehl, den der Test ausfuehrt: rein lesende CIM-Abfragen
// (Computersystem + Betriebssystem), Ausgabe als "Schluessel=Wert"-Zeilen. Der Text ist fest
// im Programm, es wird nie etwas aus Benutzereingaben eingesetzt. Nur ASCII, damit die
// Konsolen-Codepage keine Rolle spielt.
const winrmInfoCommand = `powershell -NoProfile -NonInteractive -Command "` +
	`$c=Get-CimInstance Win32_ComputerSystem; $o=Get-CimInstance Win32_OperatingSystem; ` +
	`'Name='+$c.Name; 'Domain='+$c.Domain; 'InDomain='+$c.PartOfDomain; ` +
	`'Maker='+$c.Manufacturer; 'Model='+$c.Model; ` +
	`'OS='+$o.Caption; 'Build='+$o.Version; ` +
	`'UptimeSec='+[int]((Get-Date)-$o.LastBootUpTime).TotalSeconds"`

// winrmTimeout begrenzt den gesamten Test (Verbindung + Anmeldung + Befehl).
const winrmTimeout = 20 * time.Second

// WinRM testet die Anmeldung mit Benutzer/Passwort. Domaenenkonten: "DOMAENE\benutzer" oder "benutzer@domaene".
func WinRM(ctx context.Context, host, user, password string) Result {
	res := Result{Method: MethodWinRM, Port: WinRMPort, At: time.Now()}

	endpoint := winrm.NewEndpoint(host, WinRMPort, false, false, nil, nil, nil, dialTimeout)
	enc, err := winrm.NewEncryption("ntlm")
	if err != nil {
		res.Status, res.Message = StatusUnavailable, "NTLM-Verschlüsselung nicht verfügbar"
		return res
	}
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return enc }
	client, err := winrm.NewClientWithParameters(endpoint, user, password, params)
	if err != nil {
		res.Status, res.Message = StatusUnavailable, "WinRM-Verbindung nicht möglich"
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, winrmTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code, err := client.RunWithContext(ctx, winrmInfoCommand, &stdout, &stderr)
	if err != nil {
		res.Status, res.Message = classifyWinRMError(err, password)
		return res
	}
	res.Status = StatusOK
	res.Message = "Anmeldung per WinRM akzeptiert"
	if code == 0 {
		res.Info = parseWinRMInfo(stdout.String())
	}
	if len(res.Info) == 0 {
		// PowerShell/CIM nicht nutzbar: Login war trotzdem ok, nur ohne Zusatzinfos.
		res.Message += " (keine System-Infos lesbar)"
	}
	return res
}

// parseWinRMInfo wertet die "Schluessel=Wert"-Zeilen aus winrmInfoCommand aus und liefert
// beschriftete Felder (Computername, Domaene/Arbeitsgruppe, Modell, System, Laufzeit).
// Unbekannte Zeilen und leere Werte werden ignoriert; alle Werte werden bereinigt.
// Reine Logik, ohne Netzwerk testbar.
func parseWinRMInfo(raw string) []Field {
	vals := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			vals[k] = cleanValue(strings.TrimSpace(v))
		}
	}
	var out []Field
	add := func(name, value string) {
		if value != "" {
			out = append(out, Field{Name: name, Value: value})
		}
	}
	add("Computername", vals["Name"])
	// Domaenenmitglied oder Arbeitsgruppe: der Wert "Domain" bedeutet je nach "InDomain" etwas anderes.
	if strings.EqualFold(vals["InDomain"], "True") {
		add("Domäne", vals["Domain"])
	} else {
		add("Arbeitsgruppe", vals["Domain"])
	}
	add("Modell", strings.TrimSpace(vals["Maker"]+" "+vals["Model"]))
	add("System", strings.TrimSpace(vals["OS"]+" "+vals["Build"]))
	if up, ok := parseUptime(vals["UptimeSec"]); ok {
		add("Laufzeit", up)
	}
	return out
}

// classifyWinRMError ordnet einen Fehler ein: 401 = Konto/Passwort abgelehnt, alles andere
// (Port zu, Zeitueberschreitung, WinRM aus, Verschluesselung nicht erlaubt) = nicht testbar.
// Reine Logik, ohne Netzwerk testbar. Das Passwort wird aus der Meldung entfernt.
func classifyWinRMError(err error, password string) (Status, string) {
	t := strings.ToLower(err.Error())
	if strings.Contains(t, "401") || strings.Contains(t, "unauthorized") {
		return StatusFailed, "Anmeldung abgelehnt (Konto/Passwort falsch oder Konto ohne WinRM-Recht)"
	}
	return StatusUnavailable, "WinRM nicht erreichbar oder nicht testbar: " + cleanErr(err, password)
}
