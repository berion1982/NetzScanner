package logintest

// SMB-Login-Test (I-022 Rest): prueft, ob ein Windows-Rechner, Domaenencontroller, NAS oder
// Samba-Server die Anmeldung per SMB (Port 445) mit Benutzer/Passwort akzeptiert.
//
// Regeln (wie bei den anderen Login-Tests):
//   - genau EIN Anmeldeversuch pro Aufruf (Konto-Sperren vermeiden), kein Wiederholen;
//   - Anmeldeart ist NTLM: Das Passwort geht NIE im Klartext ueber das Netz, sondern nur als
//     Challenge-Response (Hash). Deshalb gibt es hier keine Fingerabdruck-/Klartext-Rueckfrage;
//   - leeres Passwort wird nie gesendet (waere ein anonymer/Gast-Zugang und damit ein falsches "ok");
//   - nach der Anmeldung nur lesend: die Namen der Freigaben (Share-Liste ueber IPC$/srvsvc).
//     Es wird nichts geschrieben, kein Share eingebunden und keine Datei geoeffnet;
//   - nur Port 445 (SMB direkt ueber TCP). NetBIOS-Transport (Port 139) wird nicht unterstuetzt.
// Das Passwort taucht in keiner Meldung auf.

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// MethodSMB ist der Methodenname fuer Ergebnis und Oberflaeche.
const MethodSMB = "smb"

// SMBPort ist der Standard-Port fuer SMB direkt ueber TCP.
const SMBPort = 445

// smbTimeout begrenzt den gesamten Test (Verbindung + Anmeldung + Freigabeliste).
const smbTimeout = 20 * time.Second

// maxSMBShares begrenzt, wie viele Freigabenamen in der Anzeige landen.
const maxSMBShares = 20

// NTSTATUS-Codes, die der Server bei einer abgelehnten Anmeldung liefert (laut [MS-ERREF]).
const (
	ntLogonFailure      uint32 = 0xC000006D // Benutzer oder Authentifizierung ungueltig
	ntWrongPassword     uint32 = 0xC000006A // Passwort falsch
	ntNoSuchUser        uint32 = 0xC0000064 // Benutzer unbekannt
	ntAccountRestricted uint32 = 0xC000006E // Konto-Einschraenkung (z. B. Anmeldezeiten)
	ntPasswordExpired   uint32 = 0xC0000071 // Passwort abgelaufen
	ntAccountDisabled   uint32 = 0xC0000072 // Konto deaktiviert
	ntAccountLockedOut  uint32 = 0xC0000234 // Konto gesperrt
	ntAccessDenied      uint32 = 0xC0000022 // Zugriff verweigert
)

// SMB testet die NTLM-Anmeldung mit Benutzer/Passwort. Domaenenkonten: "DOMAENE\benutzer";
// "benutzer@domaene.tld" wird unveraendert an den Server gereicht.
func SMB(ctx context.Context, host, user, password string) (res Result) {
	res = Result{Method: MethodSMB, Port: SMBPort, At: time.Now()}
	if user == "" || password == "" {
		res.Status = StatusUnavailable
		res.Message = "Für SMB werden Benutzer und Passwort gebraucht (ohne Passwort wäre es ein Gast-Zugang). Es wurde nichts gesendet."
		return res
	}
	// Die Bibliothek ist fremder Code und liest Daten vom (womoeglich feindlichen) Server:
	// ein Absturz darf nie das ganze Programm mitreissen.
	defer func() {
		if r := recover(); r != nil {
			res.Status, res.Message = StatusUnavailable, "SMB-Antwort nicht auswertbar"
			res.Info = nil
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, smbTimeout)
	defer cancel()

	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(SMBPort)))
	if err != nil {
		res.Status, res.Message = StatusUnavailable, "Keine Verbindung zu Port 445 (geschlossen oder gesperrt)"
		return res
	}
	defer conn.Close()
	// Haengt der Server, schliesst die Frist die Verbindung statt den Test ewig warten zu lassen.
	_ = conn.SetDeadline(time.Now().Add(smbTimeout))

	domain, account := splitSMBUser(user)
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: account, Password: password, Domain: domain}}

	// Genau ein Anmeldeversuch (Verhandlung + NTLM-Sitzungsaufbau).
	session, err := d.DialContext(ctx, conn)
	if err != nil {
		res.Status, res.Message = classifySMBError(err, password)
		return res
	}
	defer session.Logoff() //nolint:errcheck // Abmelden ist nur Aufraeumen

	res.Status = StatusOK
	res.Message = "SMB-Anmeldung akzeptiert"
	res.Info = smbShareInfo(session.WithContext(ctx))
	if len(res.Info) == 0 {
		// Freigabeliste verweigert (z. B. Konto ohne Recht): Login war trotzdem ok.
		res.Message += " (Freigabeliste nicht lesbar)"
	}
	return res
}

// splitSMBUser trennt "DOMAENE\benutzer" in Domaene und Konto. Andere Schreibweisen
// ("benutzer", "benutzer@domaene.tld") bleiben unveraendert als Konto (Domaene leer).
// Reine Logik, ohne Netzwerk testbar.
func splitSMBUser(user string) (domain, account string) {
	user = strings.TrimSpace(user)
	if d, a, ok := strings.Cut(user, `\`); ok && a != "" {
		return d, a
	}
	return "", user
}

// smbShareInfo liest die Namen der Freigaben (nur lesend). Fehler fuehren nur zu leeren Infos.
// Die Namen kommen vom Server und werden bereinigt, sortiert und in der Anzahl begrenzt.
func smbShareInfo(session *smb2.Session) []Field {
	names, err := session.ListSharenames()
	if err != nil || len(names) == 0 {
		return nil
	}
	return shareFields(names)
}

// shareFields macht aus den Freigabenamen ein beschriftetes Feld. Reine Logik, ohne Netzwerk testbar.
func shareFields(names []string) []Field {
	var clean []string
	for _, n := range names {
		if v := cleanValue(strings.TrimSpace(n)); v != "" {
			clean = append(clean, v)
		}
	}
	if len(clean) == 0 {
		return nil
	}
	sort.Strings(clean)
	more := ""
	if len(clean) > maxSMBShares {
		more = " … (+" + strconv.Itoa(len(clean)-maxSMBShares) + " weitere)"
		clean = clean[:maxSMBShares]
	}
	return []Field{{Name: "Freigaben", Value: strings.Join(clean, ", ") + more}}
}

// classifySMBError ordnet einen Fehler der Anmeldung ein: Ablehnung durch den Server
// (falsches Konto/Passwort, gesperrt, deaktiviert ...) = abgelehnt; alles andere
// (Netzwerk, Zeitlimit, Server erlaubt NTLM nicht) = nicht testbar.
// Reine Logik, ohne Netzwerk testbar. Das Passwort wird aus der Meldung entfernt.
func classifySMBError(err error, password string) (Status, string) {
	var re *smb2.ResponseError
	if errors.As(err, &re) {
		switch re.Code {
		case ntLogonFailure, ntWrongPassword, ntNoSuchUser:
			return StatusFailed, "SMB-Anmeldung abgelehnt (Benutzer/Passwort falsch)"
		case ntAccountLockedOut:
			return StatusFailed, "SMB-Anmeldung abgelehnt: Konto gesperrt (zu viele Fehlversuche?)"
		case ntAccountDisabled:
			return StatusFailed, "SMB-Anmeldung abgelehnt: Konto deaktiviert"
		case ntPasswordExpired:
			return StatusFailed, "SMB-Anmeldung abgelehnt: Passwort abgelaufen"
		case ntAccountRestricted:
			return StatusFailed, "SMB-Anmeldung abgelehnt: Konto-Einschränkung (z. B. Anmeldezeiten)"
		case ntAccessDenied:
			return StatusFailed, "SMB-Anmeldung abgelehnt (Zugriff verweigert)"
		}
	}
	// Mit erzwungener Signierung wird ein Gast-Zugang abgewiesen; die Bibliothek meldet das so.
	if strings.Contains(strings.ToLower(err.Error()), "guest") {
		return StatusFailed, "SMB-Anmeldung abgelehnt (Server bildet das Konto auf Gast ab)"
	}
	return StatusUnavailable, "SMB nicht erreichbar oder nicht testbar: " + cleanErr(err, password)
}
