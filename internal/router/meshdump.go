package router

// Diagnose der Mesh-Liste (I-055 c): Die FRITZ!Box nennt über die TR-064-Aktion
// X_AVM-DE_GetMeshListPath einen Pfad zu einem Dokument (nach meinem Wissen JSON), das die
// Mesh-Verbindungen beschreibt. Ich WEISS NICHT, wie dieses Dokument bei Saschas Box aufgebaut ist.
// Statt zu raten, holt dieser Befehl das Dokument ab und gibt es ROH aus, damit der Parser
// danach auf echten Daten gebaut werden kann.
//
// Nur lesend: ein SOAP-Aufruf + ein GET. Die Zugangsdaten leben nur für die Dauer des Aufrufs.
// Ausgabe enthält Gerätenamen und MAC-Adressen – vor dem Weitergeben bitte prüfen/schwärzen.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// maxMeshDoc begrenzt das Mesh-Dokument (größer als normale Antworten, da viele Geräte möglich).
const maxMeshDoc = 2 << 20

// DumpMesh liest die Mesh-Liste der Box unter host und schreibt sie roh nach w.
func DumpMesh(ctx context.Context, host, user, pass string, w io.Writer) error {
	if net.ParseIP(host) == nil {
		return errors.New("Router-Adresse ist keine gültige IP")
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
	r, err := c.call(ctx, svcHosts, "X_AVM-DE_GetMeshListPath", "")
	if err != nil {
		return fmt.Errorf("Mesh-Pfad nicht lesbar: %w", err)
	}
	raw := r["NewX_AVM-DE_MeshListPath"]
	if raw == "" {
		return errors.New("Box liefert keinen Mesh-Pfad (Feld NewX_AVM-DE_MeshListPath leer)")
	}
	// Pfad kann absolut (http://host:port/...) oder relativ sein. Wir nutzen immer unsere Basis,
	// damit nur die angegebene Box angefragt wird. Die Session-ID (?sid=) wird NICHT ausgegeben.
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("Mesh-Pfad nicht auswertbar")
	}
	fmt.Fprintf(w, "# Mesh-Pfad (ohne Abfrageteil): %s\n", u.Path)
	body, status, err := c.getPath(ctx, u.RequestURI())
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "# HTTP-Status: %d, %d Bytes\n", status, len(body))
	_, _ = w.Write(body)
	fmt.Fprintln(w)
	return nil
}

// getPath holt einen Pfad per GET, bei 401 mit Digest (genau ein Anmeldeversuch wie in call).
func (c *client) getPath(ctx context.Context, uri string) ([]byte, int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", c.base+uri, nil)
		if err != nil {
			return nil, 0, errors.New("Anfrage nicht möglich")
		}
		if c.chal != nil {
			// Digest-URI ist der Pfad inklusive Abfrage, genau wie gesendet.
			req.Header.Set("Authorization", c.digest("GET", uri))
			c.tried = true
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, 0, errors.New("Router nicht erreichbar")
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxMeshDoc))
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			return data, resp.StatusCode, nil
		}
		ch := parseChallenge(resp.Header.Get("WWW-Authenticate"))
		if ch == nil {
			return nil, resp.StatusCode, errors.New("Router verlangt eine unbekannte Anmeldeart")
		}
		if c.tried && !strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "stale=true") {
			return nil, resp.StatusCode, ErrAuth
		}
		c.chal, c.nc = ch, 0
	}
	return nil, 0, ErrAuth
}
