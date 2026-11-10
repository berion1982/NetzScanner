// Paket logintest prueft, ob ein gemerkter Zugang (Benutzer/Passwort, I-020) an einem
// Geraet funktioniert (I-022). Unterstuetzt: SSH (Passwort / Tastatur-interaktiv)
// und Web (HTTP-Basic-Anmeldung).
//
// Sicherheitsregeln (siehe IDEAS.md, Hinweise zu I-020/I-022):
//   - Pro Aufruf wird das Passwort hoechstens EINMAL an das Geraet gesendet
//     (Schutz vor Konto-Sperren durch Fehlversuche).
//   - SSH-Hostkeys und TLS-Zertifikate werden NIE still ignoriert: Ohne bestaetigten
//     Fingerabdruck wird nur die Verbindung aufgebaut, das Passwort geht gar nicht raus;
//     das Ergebnis lautet dann StatusConfirm samt Fingerabdruck. Erst ein zweiter
//     Aufruf mit genau diesem Fingerabdruck sendet die Anmeldung.
//   - Passwoerter kommen in keinem Ergebnis- oder Fehlertext vor.
//   - Es wird nichts auf dem Geraet veraendert: SSH oeffnet keine Sitzung/Shell,
//     Web sendet nur ein GET.
package logintest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Status ist das Ergebnis eines Login-Tests.
type Status string

const (
	StatusOK          Status = "ok"          // Anmeldung wurde akzeptiert
	StatusFailed      Status = "failed"      // Anmeldung wurde abgelehnt (falsches Konto/Passwort)
	StatusConfirm     Status = "confirm"     // Fingerabdruck muss erst bestaetigt werden (kein Passwort gesendet)
	StatusUnavailable Status = "unavailable" // nicht testbar (Port zu, andere Anmeldeart, Zeitueberschreitung ...)
)

// Methoden, die getestet werden koennen.
const (
	MethodSSH = "ssh"
	MethodWeb = "web"
)

// Result ist das Ergebnis eines Tests. Enthaelt nie ein Passwort.
type Result struct {
	Method      string    `json:"method"`
	Port        int       `json:"port"`
	Scheme      string    `json:"scheme,omitempty"` // nur Web: "https" oder "http"
	Status      Status    `json:"status"`
	Message     string    `json:"message"`
	Fingerprint string    `json:"fingerprint,omitempty"` // bei StatusConfirm: zu bestaetigender Fingerabdruck
	At          time.Time `json:"at"`
}

// Zeitlimits: ein haengendes Geraet darf die Oberflaeche nicht blockieren.
const (
	dialTimeout    = 5 * time.Second
	handshakeLimit = 10 * time.Second
	webTimeout     = 8 * time.Second
)

// errNeedConfirm bricht den Verbindungsaufbau ab, bevor irgendein Passwort gesendet wird.
var errNeedConfirm = errors.New("fingerabdruck muss bestaetigt werden")

// errMismatch: der bestaetigte Fingerabdruck passt nicht mehr (anderer Schluessel/Zertifikat).
var errMismatch = errors.New("fingerabdruck weicht vom bestaetigten ab")

// ---------------------------------------------------------------- SSH

// SSH testet eine Anmeldung per Passwort bzw. Tastatur-interaktiv.
// pinned ist der vom Nutzer bestaetigte Hostkey-Fingerabdruck ("SHA256:..."); leer = erst nur anzeigen.
func SSH(ctx context.Context, host string, port int, user, password, pinned string) Result {
	res := Result{Method: MethodSSH, Port: port, At: time.Now()}
	var seen string // Fingerabdruck, den das Geraet praesentiert hat

	// Das Passwort wird hoechstens einmal gesendet: Tastatur-interaktiv wird nur dann
	// beantwortet, wenn die normale Passwort-Anmeldung nicht schon versucht wurde.
	passwordTried := false
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PasswordCallback(func() (string, error) {
				passwordTried = true
				return password, nil
			}),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				if passwordTried {
					return nil, errors.New("passwort wurde bereits versucht")
				}
				passwordTried = true
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		// Der Hostkey wird NICHT ignoriert, sondern geprueft: ohne Bestaetigung Abbruch
		// (vor jeder Anmeldung), mit Bestaetigung nur bei exakt gleichem Fingerabdruck.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = ssh.FingerprintSHA256(key)
			if pinned == "" {
				return errNeedConfirm
			}
			if seen != pinned {
				return errMismatch
			}
			return nil
		},
		Timeout: handshakeLimit,
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Status, res.Message = StatusUnavailable, "Keine Verbindung zu Port "+strconv.Itoa(port)+" (geschlossen oder gesperrt)"
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeLimit))

	client, _, _, err := ssh.NewClientConn(conn, addr, cfg)
	switch {
	case err == nil:
		// Angemeldet. Es wird bewusst keine Sitzung geoeffnet - sofort wieder trennen.
		_ = client.Close()
		res.Status, res.Message = StatusOK, "SSH-Anmeldung erfolgreich"
	case seen != "" && pinned == "":
		res.Status, res.Fingerprint = StatusConfirm, seen
		res.Message = "Hostkey noch nicht bestaetigt. Es wurde KEIN Passwort gesendet."
	case seen != "" && seen != pinned:
		res.Status, res.Fingerprint = StatusUnavailable, seen
		res.Message = "Hostkey weicht vom bestaetigten ab - Abbruch, kein Passwort gesendet."
	case strings.Contains(err.Error(), "unable to authenticate"):
		res.Status, res.Message = StatusFailed, "SSH-Anmeldung abgelehnt (Benutzer/Passwort oder Anmeldeart nicht erlaubt)"
	default:
		res.Status, res.Message = StatusUnavailable, "SSH nicht auswertbar: "+cleanErr(err, password)
	}
	return res
}

// ---------------------------------------------------------------- Web

// Web testet eine HTTP-Basic-Anmeldung auf "/" des Geraets. Es wird nur ein GET gesendet,
// und zwar nur dann MIT Zugangsdaten, wenn das Geraet ohne Anmeldung selbst 401 + "Basic" verlangt.
// Formular-Logins (HTML-Seiten) sind nicht testbar, weil ihr Aufbau je Geraet verschieden ist.
// scheme "https": pinned ist der bestaetigte Zertifikats-Fingerabdruck; "http": unverschluesselt,
// der Aufrufer muss das ausdruecklich erlaubt haben.
func Web(ctx context.Context, host string, port int, scheme, user, password, pinned string) Result {
	res := Result{Method: MethodWeb, Port: port, Scheme: scheme, At: time.Now()}
	var seen string // SHA-256-Fingerabdruck des praesentierten Zertifikats

	tr := &http.Transport{
		DialContext: (&net.Dialer{Timeout: dialTimeout}).DialContext,
		// Die uebliche Kettenpruefung wird durch eine Fingerabdruck-Pruefung ersetzt
		// (Geraete haben meist selbst signierte Zertifikate). Das ist KEIN stilles Ignorieren:
		// ohne bestaetigten Fingerabdruck bricht der Aufruf ab, bevor Daten gesendet werden.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // ersetzt durch VerifyPeerCertificate unten
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errMismatch
				}
				seen = certFingerprint(raw[0])
				if pinned == "" {
					return errNeedConfirm
				}
				if seen != pinned {
					return errMismatch
				}
				return nil
			},
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   webTimeout,
		// Weiterleitungen nicht folgen: sonst wuerde Basic-Auth ggf. an einen anderen Host gehen.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/"

	// Schritt 1: ohne Zugangsdaten fragen, ob das Geraet eine Basic-Anmeldung verlangt.
	resp, err := doGet(ctx, client, url, "", "")
	if err != nil {
		return webError(res, err, seen, pinned, password)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		res.Status = StatusUnavailable
		res.Message = fmt.Sprintf("Das Gerät verlangt auf dieser Seite keine HTTP-Anmeldung (Status %d). Formular-Logins kann der Test nicht prüfen. Es wurde kein Passwort gesendet.", resp.StatusCode)
		return res
	}
	if !wantsBasic(resp.Header.Values("WWW-Authenticate")) {
		res.Status = StatusUnavailable
		res.Message = "Das Gerät verlangt eine andere HTTP-Anmeldeart als Basic (z. B. Digest) - nicht unterstützt. Es wurde kein Passwort gesendet."
		return res
	}

	// Schritt 2: genau ein Versuch mit Zugangsdaten.
	resp, err = doGet(ctx, client, url, user, password)
	if err != nil {
		return webError(res, err, seen, pinned, password)
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		res.Status, res.Message = StatusFailed, fmt.Sprintf("HTTP-Anmeldung abgelehnt (Status %d)", resp.StatusCode)
	case resp.StatusCode < 400:
		res.Status, res.Message = StatusOK, fmt.Sprintf("HTTP-Anmeldung akzeptiert (Status %d)", resp.StatusCode)
	default:
		res.Status, res.Message = StatusUnavailable, fmt.Sprintf("Unklare Antwort nach der Anmeldung (Status %d)", resp.StatusCode)
	}
	return res
}

// doGet sendet ein GET; bei user != "" mit HTTP-Basic.
func doGet(ctx context.Context, c *http.Client, url, user, password string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NetzScanner-Logintest")
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	return c.Do(req)
}

// webError uebersetzt Verbindungsfehler in ein Ergebnis (inkl. Bestaetigungs-Fall).
func webError(res Result, err error, seen, pinned, password string) Result {
	switch {
	case errors.Is(err, errNeedConfirm) && seen != "":
		res.Status, res.Fingerprint = StatusConfirm, seen
		res.Message = "Zertifikat noch nicht bestätigt. Es wurde KEIN Passwort gesendet."
	case errors.Is(err, errMismatch):
		res.Status, res.Fingerprint = StatusUnavailable, seen
		res.Message = "Zertifikat weicht vom bestätigten ab - Abbruch, kein Passwort gesendet."
	default:
		res.Status, res.Message = StatusUnavailable, "Web nicht erreichbar: "+cleanErr(err, password)
	}
	return res
}

// wantsBasic sagt, ob einer der WWW-Authenticate-Header das Schema "Basic" anbietet.
func wantsBasic(headers []string) bool {
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(h)), "basic") {
			return true
		}
	}
	return false
}

// certFingerprint liefert den SHA-256-Fingerabdruck eines DER-Zertifikats ("AB:CD:...").
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// cleanErr kuerzt Fehlertexte und entfernt sicherheitshalber das Passwort daraus.
func cleanErr(err error, password string) string {
	t := err.Error()
	if password != "" {
		t = strings.ReplaceAll(t, password, "***")
	}
	if len(t) > 160 {
		t = t[:160] + "…"
	}
	return t
}
