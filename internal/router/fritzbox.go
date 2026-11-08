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
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Grenzen und Konstanten.
const (
	tr064Port      = "49000"                            // unverschluesselter TR-064-Port der FRITZ!Box
	hostsControl   = "/upnp/control/hosts"              // Steuer-URL des Dienstes Hosts:1
	hostsService   = "urn:dslforum-org:service:Hosts:1" // Dienst-Kennung
	maxEntries     = 1000                               // hoechstens so viele Geraete lesen
	maxResponse    = 64 << 10                           // Antworten auf 64 KiB begrenzen
	requestTimeout = 6 * time.Second                    // je Anfrage
	maxNameRunes   = 64
)

// tr064PortOverride ersetzt den Port nur in Tests (leer = tr064Port).
var tr064PortOverride string

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

// ReadFritzbox liest die Geraeteliste der FRITZ!Box unter host (IP-Adresse). Kontext zum Abbrechen.
func ReadFritzbox(ctx context.Context, host, user, pass string) ([]Host, error) {
	if net.ParseIP(host) == nil {
		return nil, errors.New("Router-Adresse ist keine gültige IP")
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
	body, err := c.soap(ctx, "GetHostNumberOfEntries", "")
	if err != nil {
		return nil, err
	}
	var cnt struct {
		N int `xml:"Body>GetHostNumberOfEntriesResponse>NewHostNumberOfEntries"`
	}
	if err := xml.Unmarshal(body, &cnt); err != nil || cnt.N < 0 {
		return nil, errors.New("unerwartete Antwort des Routers (TR-064 aktiv?)")
	}
	if cnt.N > maxEntries {
		cnt.N = maxEntries
	}
	var out []Host
	for i := 0; i < cnt.N; i++ {
		b, err := c.soap(ctx, "GetGenericHostEntry", "<NewIndex>"+strconv.Itoa(i)+"</NewIndex>")
		if err != nil {
			return out, err
		}
		var e struct {
			IP    string `xml:"Body>GetGenericHostEntryResponse>NewIPAddress"`
			MAC   string `xml:"Body>GetGenericHostEntryResponse>NewMACAddress"`
			Src   string `xml:"Body>GetGenericHostEntryResponse>NewAddressSource"`
			Iface string `xml:"Body>GetGenericHostEntryResponse>NewInterfaceType"`
			Act   string `xml:"Body>GetGenericHostEntryResponse>NewActive"`
			Name  string `xml:"Body>GetGenericHostEntryResponse>NewHostName"`
		}
		if xml.Unmarshal(b, &e) != nil {
			continue // kaputter Eintrag: ueberspringen
		}
		out = append(out, Host{IP: clean(e.IP, 45), MAC: clean(e.MAC, 17), Name: clean(e.Name, maxNameRunes),
			Iface: ifaceLabel(e.Iface), Active: e.Act == "1" || strings.EqualFold(e.Act, "true"), Source: clean(e.Src, 16)})
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

// soap ruft eine Aktion des Hosts-Dienstes auf und liefert den Antwort-Koerper.
// Ablauf: erst ohne Anmeldung (liefert 401 + Herausforderung), dann genau einmal mit Digest.
func (c *client) soap(ctx context.Context, action, args string) ([]byte, error) {
	envelope := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + hostsService + `">` +
		args + `</u:` + action + `></s:Body></s:Envelope>`
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", c.base+hostsControl, strings.NewReader(envelope))
		if err != nil {
			return nil, errors.New("Anfrage nicht möglich")
		}
		req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
		req.Header.Set("SoapAction", hostsService+"#"+action)
		if c.chal != nil {
			req.Header.Set("Authorization", c.digest("POST", hostsControl))
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
			return data, nil
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
			return nil, fmt.Errorf("Router antwortet mit Status %d (TR-064 aktiv? Dienst vorhanden?)", resp.StatusCode)
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
