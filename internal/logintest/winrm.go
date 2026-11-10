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
	code, err := client.RunWithContext(ctx, "hostname", &stdout, &stderr)
	if err != nil {
		res.Status, res.Message = classifyWinRMError(err, password)
		return res
	}
	res.Status = StatusOK
	res.Message = "Anmeldung per WinRM akzeptiert"
	if name := cleanValue(stdout.String()); name != "" && code == 0 {
		res.Info = []Field{{Name: "Computername", Value: name}}
	}
	return res
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
