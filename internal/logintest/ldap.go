package logintest

// LDAP-Login-Test (I-022 Rest): prueft, ob ein Verzeichnisdienst (z. B. Active-Directory-
// Domaenencontroller, OpenLDAP) die Anmeldung per LDAP-Bind mit Benutzer/Passwort akzeptiert.
//
// Regeln (wie bei SSH/Web):
//   - genau EIN Bind-Versuch pro Aufruf (Konto-Sperren vermeiden), kein Wiederholen;
//   - verschluesselt zuerst: Port 636/3269 = LDAPS, Port 389/3268 = StartTLS. Das Zertifikat
//     wird nie still ignoriert: erst Fingerabdruck anzeigen und bestaetigen lassen, dann binden;
//   - unverschluesselter Bind (Passwort im Klartext) nur, wenn der Server kein StartTLS kann
//     UND der Aufrufer es ausdruecklich erlaubt hat (allowPlain);
//   - leeres Passwort wird nie gesendet (ein "unauthenticated bind" waere sonst faelschlich "ok");
//   - nach dem Bind nur lesend: die rootDSE (Domaene, Servername) - es wird nichts geschrieben.
// Das Passwort taucht in keiner Meldung auf.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// MethodLDAP ist der Methodenname fuer Ergebnis und Oberflaeche.
const MethodLDAP = "ldap"

// ldapTimeout begrenzt den gesamten Test (Verbindung + TLS + Bind + rootDSE).
const ldapTimeout = 20 * time.Second

// ldapTLSPorts sind die Ports, auf denen TLS von Anfang an gesprochen wird (LDAPS, Global Catalog TLS).
// Alle anderen LDAP-Ports starten unverschluesselt und werden per StartTLS gesichert.
var ldapTLSPorts = map[int]bool{636: true, 3269: true}

// LDAPPorts sind die Ports, fuer die die Oberflaeche den LDAP-Test anbietet.
var LDAPPorts = []int{389, 636, 3268, 3269}

// IsLDAPPort sagt, ob der Port ein bekannter LDAP-Port ist.
func IsLDAPPort(port int) bool {
	for _, p := range LDAPPorts {
		if p == port {
			return true
		}
	}
	return false
}

// SchemePlain im Ergebnis bedeutet: Der Server kann kein TLS; ein Bind ginge im Klartext.
// Es wurde KEIN Passwort gesendet - die Oberflaeche muss erst ausdruecklich nachfragen.
const SchemePlain = "plain"

// ldapTrust haelt die Fingerabdruck-Pruefung fuer eine Verbindung.
type ldapTrust struct {
	pinned      string // vom Nutzer bestaetigter Fingerabdruck ("" = erst nur anzeigen)
	seen        string // Fingerabdruck, den der Server praesentiert hat
	needConfirm bool   // Fingerabdruck war noch nicht bestaetigt
	mismatch    bool   // Fingerabdruck weicht vom bestaetigten ab
}

// config baut die TLS-Einstellungen: Die uebliche Kettenpruefung wird durch die
// Fingerabdruck-Pruefung ersetzt (Verzeichnisserver haben oft eigene Zertifikate).
// Das ist KEIN stilles Ignorieren: ohne bestaetigten Fingerabdruck bricht der Aufbau ab,
// bevor ein Passwort gesendet wird.
func (t *ldapTrust) config(host string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // ersetzt durch VerifyPeerCertificate unten
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				t.mismatch = true
				return errMismatch
			}
			t.seen = certFingerprint(raw[0])
			if t.pinned == "" {
				t.needConfirm = true
				return errNeedConfirm
			}
			if t.seen != t.pinned {
				t.mismatch = true
				return errMismatch
			}
			return nil
		},
	}
}

// LDAP testet den Bind mit Benutzer/Passwort. Als Benutzer gelten die in AD ueblichen Formen
// "DOMAENE\benutzer", "benutzer@domaene.tld" oder ein vollstaendiger DN.
// pinned ist der bestaetigte Zertifikats-Fingerabdruck; allowPlain erlaubt einen Klartext-Bind.
func LDAP(ctx context.Context, host string, port int, user, password, pinned string, allowPlain bool) Result {
	res := Result{Method: MethodLDAP, Port: port, At: time.Now()}
	if user == "" || password == "" {
		res.Status = StatusUnavailable
		res.Message = "Für LDAP werden Benutzer und Passwort gebraucht (leeres Passwort wäre ein anonymer Bind). Es wurde nichts gesendet."
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, ldapTimeout)
	defer cancel()

	trust := &ldapTrust{pinned: pinned}
	conn, encrypted, err := ldapConnect(ctx, host, port, trust, allowPlain)
	if err != nil {
		return ldapConnectError(res, err, trust, password)
	}
	defer conn.Close()
	stop := closeOnDone(ctx, conn)
	defer stop()

	// Genau ein Bind-Versuch.
	if err := conn.Bind(user, password); err != nil {
		res.Status, res.Message = classifyLDAPBindError(err, password)
		return res
	}
	res.Status = StatusOK
	if encrypted {
		res.Message = "LDAP-Anmeldung akzeptiert (verschlüsselt)"
		res.Scheme = "tls"
	} else {
		res.Message = "LDAP-Anmeldung akzeptiert (UNVERSCHLÜSSELT, Passwort ging im Klartext)"
		res.Scheme = SchemePlain
	}
	res.Info = readRootDSE(conn)
	return res
}

// ldapConnect baut die Verbindung auf: LDAPS auf TLS-Ports, sonst StartTLS; Klartext nur mit allowPlain.
// Rueckgabe: Verbindung, ob sie verschluesselt ist, und ein Fehler. Es wird noch nichts gebunden.
func ldapConnect(ctx context.Context, host string, port int, trust *ldapTrust, allowPlain bool) (*ldap.Conn, bool, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: dialTimeout}

	if ldapTLSPorts[port] {
		conn, err := ldap.DialURL("ldaps://"+addr,
			ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(trust.config(host)))
		if err != nil {
			return nil, false, err
		}
		conn.SetTimeout(handshakeLimit)
		return conn, true, nil
	}

	// Klartext-Port: erst StartTLS versuchen.
	conn, err := ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(dialer))
	if err != nil {
		return nil, false, err
	}
	conn.SetTimeout(handshakeLimit)
	stop := closeOnDone(ctx, conn)
	err = conn.StartTLS(trust.config(host))
	stop()
	if err == nil {
		return conn, true, nil
	}
	conn.Close()
	// Fingerabdruck offen/abweichend: der Aufrufer behandelt das ueber trust.
	if trust.needConfirm || trust.mismatch {
		return nil, false, err
	}
	// Antwortet der Server mit einem LDAP-Fehler (kein Netzwerkfehler), kann er kein StartTLS.
	var le *ldap.Error
	if !asLDAPError(err, &le) || le.ResultCode == ldap.ErrorNetwork {
		return nil, false, err
	}
	if !allowPlain {
		return nil, false, errPlainNeedsConfirm
	}
	// Ausdruecklich erlaubt: neue, unverschluesselte Verbindung.
	plain, err := ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(dialer))
	if err != nil {
		return nil, false, err
	}
	plain.SetTimeout(handshakeLimit)
	return plain, false, nil
}

// errPlainNeedsConfirm: Der Server kann kein StartTLS; ein Bind waere Klartext und braucht Bestaetigung.
var errPlainNeedsConfirm = errorString("ldap: nur unverschluesselt moeglich")

// errorString ist ein minimaler Fehlertyp fuer feste Meldungen.
type errorString string

func (e errorString) Error() string { return string(e) }

// asLDAPError zieht einen *ldap.Error aus dem Fehler (auch wenn er verpackt ist).
func asLDAPError(err error, target **ldap.Error) bool {
	for err != nil {
		if le, ok := err.(*ldap.Error); ok {
			*target = le
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ldapConnectError uebersetzt Verbindungsfehler in ein Ergebnis (inkl. Bestaetigungs-Faelle).
// Reine Logik, ohne Netzwerk testbar.
func ldapConnectError(res Result, err error, trust *ldapTrust, password string) Result {
	switch {
	case trust.needConfirm && trust.seen != "":
		res.Status, res.Fingerprint = StatusConfirm, trust.seen
		res.Message = "Zertifikat noch nicht bestätigt. Es wurde KEIN Passwort gesendet."
	case trust.mismatch:
		res.Status, res.Fingerprint = StatusUnavailable, trust.seen
		res.Message = "Zertifikat weicht vom bestätigten ab - Abbruch, kein Passwort gesendet."
	case err == errPlainNeedsConfirm:
		// Status "confirm" ohne Fingerabdruck + Scheme "plain": Oberflaeche fragt nach Klartext.
		res.Status, res.Scheme = StatusConfirm, SchemePlain
		res.Message = "Der Server unterstützt kein StartTLS. Ein Bind würde das Passwort im Klartext senden. Es wurde KEIN Passwort gesendet."
	default:
		res.Status, res.Message = StatusUnavailable, "LDAP nicht erreichbar: "+cleanErr(err, password)
	}
	return res
}

// classifyLDAPBindError ordnet den Bind-Fehler ein: "Invalid Credentials" = abgelehnt,
// alles andere (Netzwerk, Zeitlimit, Server verlangt andere Anmeldeart) = nicht testbar.
// Reine Logik, ohne Netzwerk testbar. Das Passwort wird aus der Meldung entfernt.
func classifyLDAPBindError(err error, password string) (Status, string) {
	var le *ldap.Error
	if asLDAPError(err, &le) {
		switch le.ResultCode {
		case ldap.LDAPResultInvalidCredentials:
			return StatusFailed, "LDAP-Anmeldung abgelehnt (Benutzer/Passwort falsch, Konto gesperrt oder abgelaufen)"
		case ldap.LDAPResultInappropriateAuthentication, ldap.LDAPResultAuthMethodNotSupported:
			return StatusUnavailable, "Der Server erlaubt diese Anmeldeart nicht (einfacher Bind)"
		case ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultConfidentialityRequired:
			return StatusUnavailable, "Der Server verlangt eine stärkere/verschlüsselte Anmeldung"
		}
	}
	return StatusUnavailable, "LDAP-Anmeldung nicht testbar: " + cleanErr(err, password)
}

// closeOnDone schliesst die Verbindung, wenn der Kontext ablaeuft (haengender Server).
// Die zurueckgegebene Funktion beendet die Beobachtung.
func closeOnDone(ctx context.Context, conn *ldap.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// readRootDSE liest nach dem Bind die rootDSE (rein lesend, Basis "", Geltungsbereich base).
// Daraus werden Domaene und Servername abgeleitet. Fehler fuehren nur zu leeren Infos.
func readRootDSE(conn *ldap.Conn) []Field {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "dnsHostName", "ldapServiceName", "supportedLDAPVersion"}, nil)
	sr, err := conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return nil
	}
	e := sr.Entries[0]
	var out []Field
	add := func(name, value string) {
		if v := cleanValue(strings.TrimSpace(value)); v != "" {
			out = append(out, Field{Name: name, Value: v})
		}
	}
	add("Domäne", domainFromDN(e.GetAttributeValue("defaultNamingContext")))
	add("Server", e.GetAttributeValue("dnsHostName"))
	return out
}

// domainFromDN macht aus "DC=firma,DC=local" den DNS-Namen "firma.local".
// Enthaelt der DN keine DC-Teile (z. B. "o=firma"), bleibt die Domaene leer.
// Reine Logik, ohne Netzwerk testbar.
func domainFromDN(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(rdn), "=")
		if ok && strings.EqualFold(k, "dc") && v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ".")
}
