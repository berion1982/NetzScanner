package logintest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// startSSH startet einen minimalen SSH-Server (Benutzer "admin", Passwort "geheim")
// und liefert Port, Hostkey-Fingerabdruck und einen Zaehler der Passwort-Versuche.
func startSSH(t *testing.T) (port int, fp string, tries *int32) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	tries = new(int32)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			atomic.AddInt32(tries, 1)
			if c.User() == "admin" && string(pw) == "geheim" {
				return nil, nil
			}
			return nil, errBad
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					for ch := range chans {
						_ = ch.Reject(ssh.Prohibited, "test")
					}
				}()
				_ = sc.Wait()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey()), tries
}

var errBad = net.ErrClosed // beliebiger Fehler: "abgelehnt"

// Ohne bestaetigten Hostkey wird KEIN Passwort gesendet, nur der Fingerabdruck gemeldet.
func TestSSHNeedsConfirmBeforePassword(t *testing.T) {
	port, fp, tries := startSSH(t)
	r := SSH(context.Background(), "127.0.0.1", port, "admin", "geheim", "")
	if r.Status != StatusConfirm || r.Fingerprint != fp {
		t.Fatalf("erwartet confirm/%s, bekam %+v", fp, r)
	}
	if atomic.LoadInt32(tries) != 0 {
		t.Fatal("Passwort wurde trotz fehlender Bestaetigung gesendet")
	}
}

// Mit bestaetigtem Fingerabdruck: richtiges Passwort ok, falsches abgelehnt - jeweils genau ein Versuch.
func TestSSHLoginOKAndFailed(t *testing.T) {
	port, fp, tries := startSSH(t)
	if r := SSH(context.Background(), "127.0.0.1", port, "admin", "geheim", fp); r.Status != StatusOK {
		t.Fatalf("ok erwartet: %+v", r)
	}
	atomic.StoreInt32(tries, 0)
	r := SSH(context.Background(), "127.0.0.1", port, "admin", "falsch", fp)
	if r.Status != StatusFailed {
		t.Fatalf("failed erwartet: %+v", r)
	}
	if n := atomic.LoadInt32(tries); n != 1 {
		t.Fatalf("genau 1 Passwortversuch erwartet, waren %d", n)
	}
	if strings.Contains(r.Message, "falsch") {
		t.Fatal("Passwort im Ergebnistext")
	}
}

// Ein anderer als der bestaetigte Hostkey fuehrt zum Abbruch ohne Passwort.
func TestSSHHostKeyMismatch(t *testing.T) {
	port, _, tries := startSSH(t)
	r := SSH(context.Background(), "127.0.0.1", port, "admin", "geheim", "SHA256:anderer")
	if r.Status != StatusUnavailable || atomic.LoadInt32(tries) != 0 {
		t.Fatalf("Abbruch ohne Passwort erwartet: %+v (Versuche %d)", r, atomic.LoadInt32(tries))
	}
}

// Geschlossener Port -> nicht testbar.
func TestSSHClosedPort(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if r := SSH(context.Background(), "127.0.0.1", port, "a", "b", ""); r.Status != StatusUnavailable {
		t.Fatalf("unavailable erwartet: %+v", r)
	}
}

// basicServer: HTTPS-Server, der "/" nur mit admin/geheim freigibt.
func basicServer(t *testing.T, hits *int32) (host string, port int) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok {
			atomic.AddInt32(hits, 1)
		}
		if !ok || u != "admin" || p != "geheim" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return hostPort(t, srv.URL)
}

func hostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, _ := url.Parse(raw)
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p
}

// Ohne bestaetigtes Zertifikat geht kein Passwort raus; mit Fingerabdruck klappt ok/failed.
func TestWebBasicFlow(t *testing.T) {
	var hits int32
	host, port := basicServer(t, &hits)

	r := Web(context.Background(), host, port, "https", "admin", "geheim", "")
	if r.Status != StatusConfirm || r.Fingerprint == "" {
		t.Fatalf("confirm erwartet: %+v", r)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("Zugangsdaten vor der Bestaetigung gesendet")
	}
	fp := r.Fingerprint

	if r := Web(context.Background(), host, port, "https", "admin", "geheim", fp); r.Status != StatusOK {
		t.Fatalf("ok erwartet: %+v", r)
	}
	atomic.StoreInt32(&hits, 0)
	r = Web(context.Background(), host, port, "https", "admin", "falsch", fp)
	if r.Status != StatusFailed || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("failed mit genau 1 Versuch erwartet: %+v (%d)", r, atomic.LoadInt32(&hits))
	}
	if r := Web(context.Background(), host, port, "https", "admin", "geheim", "AA:BB"); r.Status != StatusUnavailable {
		t.Fatalf("Zertifikat-Abweichung muss abbrechen: %+v", r)
	}
}

// Seiten ohne 401 (z. B. Formular-Login) werden nicht mit Zugangsdaten angefragt.
func TestWebNoBasicChallenge(t *testing.T) {
	var got int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			atomic.AddInt32(&got, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	r := Web(context.Background(), host, port, "http", "admin", "geheim", "")
	if r.Status != StatusUnavailable || atomic.LoadInt32(&got) != 0 {
		t.Fatalf("unavailable ohne Passwort erwartet: %+v", r)
	}
}

// Digest statt Basic: nicht unterstuetzt, kein Passwort gesendet.
func TestWebDigestNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Digest realm="x"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	if r := Web(context.Background(), host, port, "http", "a", "b", ""); r.Status != StatusUnavailable {
		t.Fatalf("unavailable erwartet: %+v", r)
	}
}

// I-023 Rest: WebInfo liest nach EINEM erfolgreichen Basic-Login Titel, Server, Realm und Generator.
func TestWebInfoReadsPage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Testgeraet"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Server", "TestHTTPd/1.2")
		_, _ = w.Write([]byte(`<html><head><title> Router  Verwaltung </title><meta name="generator" content="TestCMS 3"></head></html>`))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	fp := Web(context.Background(), host, port, "https", "a", "b", "").Fingerprint

	r := WebInfo(context.Background(), host, port, "https", "a", "b", fp)
	if r.Status != StatusOK {
		t.Fatalf("ok erwartet: %+v", r)
	}
	got := map[string]string{}
	for _, f := range r.Info {
		got[f.Name] = f.Value
	}
	want := map[string]string{"Seitentitel": "Router  Verwaltung", "Server-Kennung": "TestHTTPd/1.2", "Anmelde-Realm": "Testgeraet", "Generator": "TestCMS 3"}
	for k, v := range want {
		if strings.TrimSpace(got[k]) != v {
			t.Errorf("%s: erwartet %q, bekam %q", k, v, got[k])
		}
	}
	// Ohne Info-Wunsch bleibt Info leer.
	if r := Web(context.Background(), host, port, "https", "a", "b", fp); len(r.Info) != 0 {
		t.Errorf("Web darf keine Infos liefern: %+v", r.Info)
	}
}
