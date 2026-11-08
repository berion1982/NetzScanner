// Package router liest Geraetelisten direkt aus Routern aus (I-024).
//
// Derzeit unterstuetzt: FRITZ!Box ueber TR-064 (SOAP, Dienst "Hosts:1"). Die FRITZ!Box kennt
// jedes Geraet, das je im Heimnetz war - mit Namen, MAC, Verbindungsart (WLAN/LAN) und
// Aktivitaet. Das ergaenzt den Scan (Namen statt "(unbekannt)").
//
// Sicherheit (Zugangsdaten!):
//   - Benutzer und Passwort leben nur in diesem Aufruf (RAM) und werden nie gespeichert,
//     nie protokolliert und nie in Fehlertexte uebernommen.
//   - Pro Aufruf gibt es genau EINEN Anmeldeversuch (Schutz vor Konto-/Anmeldesperren):
//     wird die Anmeldung abgelehnt, bricht alles sofort ab.
//   - Die Anmeldung nutzt HTTP-Digest (Passwort geht nicht im Klartext ueber das Netz); die
//     Antworten (Geraetenamen) sind bei HTTP aber lesbar. Es wird kein TLS-Zertifikat
//     ignoriert, weil gar kein TLS verwendet wird.
//   - Es wird nicht auf Weiterleitungen gefolgt, Antworten sind in der Groesse begrenzt.
//
// Ehrlich zur Technik: Das Verhalten gegen eine echte FRITZ!Box ist in der Entwicklung nur
// gegen einen Test-Server geprueft. Voraussetzung an der Box: "Zugriff fuer Anwendungen"
// (TR-064) aktiv und ein Benutzer mit dem Recht "FRITZ!Box Einstellungen".
package router

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Grenzen und Konstanten.
const (
	tr064Port      = "49000"         // unverschluesselter TR-064-Port der FRITZ!Box
	maxEntries     = 1000            // hoechstens so viele Geraete lesen
	maxResponse    = 64 << 10        // Antworten auf 64 KiB begrenzen
	requestTimeout = 6 * time.Second // je Anfrage
	maxNameRunes   = 64
)

// tr064PortOverride ersetzt den Port nur in Tests (leer = tr064Port).
var tr064PortOverride string

// service beschreibt einen TR-064-Dienst: Steuer-URL und Dienst-Kennung.
type service struct{ control, urn string }

var svcHosts = service{"/upnp/control/hosts", "urn:dslforum-org:service:Hosts:1"}

// errUnavailable: Dienst/Aktion gibt es an dieser Box nicht (404/500). Kein Anmeldefehler.
var errUnavailable = errors.New("nicht verfügbar")

// unavailableError ist errUnavailable mit Zusatzangabe (HTTP-Status, UPnP-Fehlercode/-text der Box),
// damit die Oberflaeche den echten Grund zeigen kann statt nur "nicht verfuegbar". Kein Geheimnis.
type unavailableError struct{ detail string }

func (e *unavailableError) Error() string { return errUnavailable.Error() + " (" + e.detail + ")" }
func (e *unavailableError) Unwrap() error { return errUnavailable }

// reUPnP liest errorCode/errorDescription aus der SOAP-Fehlerantwort (UPnP-Fehler).
var reUPnP = regexp.MustCompile(`(?s)<errorCode>\s*(\d{1,5})\s*</errorCode>.*?<errorDescription>\s*([^<]{0,60})`)

// faultDetail macht aus Status und Antwortkoerper eine kurze Beschreibung, z. B. "HTTP 500, UPnP 606 Action not authorized".
func faultDetail(status int, body []byte) string {
	d := "HTTP " + strconv.Itoa(status)
	if m := reUPnP.FindSubmatch(body); m != nil {
		d += ", UPnP " + string(m[1]) + " " + clean(string(m[2]), 60)
	}
	return d
}

// ErrAuth bedeutet: Benutzer/Passwort wurden abgelehnt (kein weiterer Versuch).
var ErrAuth = errors.New("Anmeldung abgelehnt (Benutzer/Passwort oder Recht „FRITZ!Box Einstellungen“ prüfen)")

// Host ist ein Geraet laut Router-Liste.
type Host struct {
	IP     string
	MAC    string // wie geliefert; zum Vergleichen normalisieren
	Name   string
	Iface  string // "WLAN", "LAN (Kabel)" oder Rohwert
	Active bool
	Source string // "DHCP", "Static" ...
}

// client haelt die Anmeldedaten nur fuer die Dauer eines Aufrufs.
type client struct {
	base  string
	user  string
	pass  string
	http  *http.Client
	chal  *challenge
	nc    int
	tried bool // Zugangsdaten wurden schon einmal gesendet
}

// challenge ist die Digest-Herausforderung der FRITZ!Box.
type challenge struct {
	realm, nonce, opaque, qop, algo string
}

// Result ist alles, was ein Router-Login liefert.
type Result struct {
	Hosts []Host
	Info  Info
	Mesh  Mesh // leer, wenn die Box keine Mesh-Liste liefert (Grund steht dann in Info.Notes)
}

// ReadFritzbox liest Geraeteliste und Netzwerkdaten der FRITZ!Box unter host (IP-Adresse).
// Kontext zum Abbrechen. Fehlende Teil-Dienste (z. B. kein drittes WLAN) sind kein Fehler.
func ReadFritzbox(ctx context.Context, host, user, pass string) (Result, error) {
	if net.ParseIP(host) == nil {
		return Result{}, errors.New("Router-Adresse ist keine gültige IP")
	}
	port := tr064Port
	if tr064PortOverride != "" {
		port = tr064PortOverride
	}
	c := &client{
		base: "http://" + net.JoinHostPort(host, port),
		user: user, pass: pass,
		http: &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	hosts, err := c.readHosts(ctx)
	if err != nil {
		return Result{Hosts: hosts}, err
	}
	info := c.readInfo(ctx) // Fehler einzelner Dienste landen in info.Notes
	res := Result{Hosts: hosts, Info: info}
	if mesh, err := c.readMesh(ctx); err == nil {
		res.Mesh = mesh
	} else { // Mesh ist optional: Grund als Hinweis, kein Abbruch
		res.Info.Notes = append(res.Info.Notes, "Mesh: "+clean(err.Error(), 160))
	}
	return res, nil
}

// readHosts liest die Geraeteliste (Dienst Hosts:1). Hier faellt auch eine falsche Anmeldung auf.
func (c *client) readHosts(ctx context.Context) ([]Host, error) {
	r, err := c.call(ctx, svcHosts, "GetHostNumberOfEntries", "")
	if err != nil {
		if errors.Is(err, errUnavailable) {
			return nil, errors.New("Router antwortet nicht wie eine FRITZ!Box (TR-064 aktiv? Dienst Hosts fehlt)")
		}
		return nil, err
	}
	n, convErr := strconv.Atoi(r["NewHostNumberOfEntries"])
	if convErr != nil || n < 0 {
		return nil, errors.New("unerwartete Antwort des Routers (TR-064 aktiv?)")
	}
	if n > maxEntries {
		n = maxEntries
	}
	var out []Host
	for i := 0; i < n; i++ {
		e, err := c.call(ctx, svcHosts, "GetGenericHostEntry", "<NewIndex>"+strconv.Itoa(i)+"</NewIndex>")
		if errors.Is(err, ErrAuth) {
			return out, err
		}
		if err != nil {
			continue // einzelner Eintrag nicht lesbar: ueberspringen
		}
		out = append(out, Host{IP: clean(e["NewIPAddress"], 45), MAC: clean(e["NewMACAddress"], 17), Name: clean(e["NewHostName"], maxNameRunes),
			Iface: ifaceLabel(e["NewInterfaceType"]), Active: e["NewActive"] == "1" || strings.EqualFold(e["NewActive"], "true"),
			Source: clean(e["NewAddressSource"], 16)})
	}
	return out, nil
}

// parseResponse liest die Kind-Elemente der SOAP-Antwort (Body > <Aktion>Response > Felder) als Name -> Text.
func parseResponse(body []byte) (map[string]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	out := map[string]string{}
	depth := 0
	var name string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 4 { // Envelope(1) > Body(2) > <Aktion>Response(3) > Feld(4)
				name = t.Name.Local
			}
		case xml.EndElement:
			if depth == 4 {
				name = ""
			}
			depth--
		case xml.CharData:
			if depth == 4 && name != "" {
				out[name] += string(t)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("leere oder unerwartete Antwort")
	}
	return out, nil
}

// ifaceLabel uebersetzt den TR-064-Schnittstellentyp.
func ifaceLabel(t string) string {
	switch strings.TrimSpace(t) {
	case "802.11":
		return "WLAN"
	case "Ethernet":
		return "LAN (Kabel)"
	}
	return clean(t, 20)
}

// clean entfernt Steuerzeichen und kuerzt (Daten aus dem Netz sind nicht vertrauenswuerdig).
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// call ruft eine TR-064-Aktion auf und liefert die Antwortfelder (Name -> Text).
// Ablauf: erst ohne Anmeldung (liefert 401 + Herausforderung), dann genau einmal mit Digest.
func (c *client) call(ctx context.Context, svc service, action, args string) (map[string]string, error) {
	envelope := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + svc.urn + `">` +
		args + `</u:` + action + `></s:Body></s:Envelope>`
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", c.base+svc.control, strings.NewReader(envelope))
		if err != nil {
			return nil, errors.New("Anfrage nicht möglich")
		}
		req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
		req.Header.Set("SoapAction", svc.urn+"#"+action)
		if c.chal != nil {
			req.Header.Set("Authorization", c.digest("POST", svc.control))
			c.tried = true
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, errors.New("Router nicht erreichbar (Adresse, Port 49000, TR-064 aktiv?)")
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			return parseResponse(data)
		case http.StatusNotFound, http.StatusInternalServerError:
			return nil, &unavailableError{faultDetail(resp.StatusCode, data)} // Dienst/Aktion fehlt oder UPnP-Fehler (z. B. nicht unterstuetzt)
		case http.StatusUnauthorized:
			ch := parseChallenge(resp.Header.Get("WWW-Authenticate"))
			if ch == nil {
				return nil, errors.New("Router verlangt eine unbekannte Anmeldeart")
			}
			// Abgelehnt, obwohl Zugangsdaten gesendet wurden: nur bei "stale" (Nonce abgelaufen)
			// ist ein erneuter Versuch kein Fehlversuch. Sonst sofort aufgeben.
			if c.tried && !strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "stale=true") {
				return nil, ErrAuth
			}
			c.chal, c.nc = ch, 0
		default:
			return nil, fmt.Errorf("Router antwortet mit Status %d", resp.StatusCode)
		}
	}
	return nil, ErrAuth
}

// parseChallenge liest "Digest realm=..., nonce=..., qop=..., algorithm=..." aus dem Header.
func parseChallenge(h string) *challenge {
	h = strings.TrimSpace(h)
	if len(h) < 7 || !strings.EqualFold(h[:7], "digest ") {
		return nil
	}
	ch := &challenge{algo: "MD5"}
	for _, part := range splitParams(h[7:]) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "realm":
			ch.realm = v
		case "nonce":
			ch.nonce = v
		case "opaque":
			ch.opaque = v
		case "qop":
			ch.qop = v
		case "algorithm":
			ch.algo = strings.ToUpper(v)
		}
	}
	if ch.nonce == "" || (ch.algo != "MD5" && ch.algo != "SHA-256") {
		return nil
	}
	return ch
}

// splitParams trennt an Kommas, aber nicht innerhalb von Anfuehrungszeichen.
func splitParams(s string) []string {
	var parts []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			cur.WriteRune(r)
		case r == ',' && !inQ:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(parts, cur.String())
}

// digest baut den Authorization-Header (RFC 2617/7616, qop=auth).
func (c *client) digest(method, uri string) string {
	ch := c.chal
	newHash := func() hash.Hash { return md5.New() }
	if ch.algo == "SHA-256" {
		newHash = sha256.New
	}
	h := func(s string) string {
		x := newHash()
		x.Write([]byte(s))
		return hex.EncodeToString(x.Sum(nil))
	}
	c.nc++
	nc := fmt.Sprintf("%08x", c.nc)
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	cnonce := hex.EncodeToString(rb[:])
	ha1 := h(c.user + ":" + ch.realm + ":" + c.pass)
	ha2 := h(method + ":" + uri)
	var resp string
	hdr := &bytes.Buffer{}
	fmt.Fprintf(hdr, `Digest username=%q, realm=%q, nonce=%q, uri=%q, algorithm=%s`, c.user, ch.realm, ch.nonce, uri, ch.algo)
	if strings.Contains(ch.qop, "auth") {
		resp = h(ha1 + ":" + ch.nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
		fmt.Fprintf(hdr, `, qop=auth, nc=%s, cnonce=%q`, nc, cnonce)
	} else {
		resp = h(ha1 + ":" + ch.nonce + ":" + ha2)
	}
	fmt.Fprintf(hdr, `, response=%q`, resp)
	if ch.opaque != "" {
		fmt.Fprintf(hdr, `, opaque=%q`, ch.opaque)
	}
	return hdr.String()
}
