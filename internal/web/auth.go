package web

// Zugriffsschutz (I-025): Wird die Oberflaeche nicht nur lokal angeboten
// (z. B. --listen 0.0.0.0:8484 auf einem Raspberry), sieht sonst jeder im
// Netz alle Scan-Daten. Deshalb gibt es ein Zugangstoken:
//
//   - Beim Start wird (ausser bei reinem Loopback) ein Zufallstoken erzeugt
//     und EINMALIG in der Konsole angezeigt; alternativ --token / Umgebung.
//   - Ohne gueltiges Token liefert der Server weder Oberflaeche noch API.
//   - Der Browser oeffnet einmal "/?token=...", der Server setzt ein Cookie
//     (HttpOnly, SameSite=Strict) und leitet auf "/" um, damit das Token
//     nicht in Adresszeile/Verlauf stehen bleibt. Skripte nutzen den Header
//     "Authorization: Bearer <Token>".
//
// Grenze (ehrlich): Die Verbindung ist weiter unverschluesselt (HTTP). Wer im
// selben Netz mitlesen kann, sieht das Token. Das Token haelt Neugierige und
// zufaellige Zugriffe fern, ersetzt aber kein TLS (spaetere Idee).

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	// tokenCookie ist der Name des Cookies, in dem der Browser das Token haelt.
	tokenCookie = "netzscanner_token"
	// MinTokenLen: kuerzere, selbst gewaehlte Tokens werden abgelehnt (Ratbarkeit).
	MinTokenLen = 8
)

// NewToken erzeugt ein zufaelliges Token (128 Bit, als 32 Hex-Zeichen).
func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// IsLoopbackListen sagt, ob die Listen-Adresse nur lokal erreichbar ist.
// Leerer Host, 0.0.0.0 und :: (alle Schnittstellen) sowie jede Nicht-Loopback-IP
// zaehlen als "offen". Ein Hostname ausser "localhost" wird vorsichtshalber
// ebenfalls als offen gewertet (Aufloesung unklar).
func IsLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// tokenOK vergleicht zeitkonstant, damit Antwortzeiten nichts verraten.
func tokenOK(given, want string) bool {
	return given != "" && subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

// requestToken liest das Token aus Bearer-Header oder Cookie (nicht aus der URL).
func requestToken(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
	}
	if c, err := r.Cookie(tokenCookie); err == nil {
		return c.Value
	}
	return ""
}

// requireToken schuetzt den gesamten Handler. Ist token leer, passiert nichts
// (reiner Loopback-Betrieb ohne --token).
func requireToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Anmeldung per "/?token=...": Cookie setzen, Token aus der URL entfernen.
		if r.Method == http.MethodGet && tokenOK(r.URL.Query().Get("token"), token) {
			http.SetCookie(w, &http.Cookie{
				Name: tokenCookie, Value: token, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
			q := r.URL.Query()
			q.Del("token")
			u := url.URL{Path: r.URL.Path, RawQuery: q.Encode()}
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, u.String(), http.StatusSeeOther)
			return
		}
		// 2. Bereits angemeldet (Cookie oder Bearer-Header)?
		if tokenOK(requestToken(r), token) {
			w.Header().Set("Cache-Control", "no-store")
			next.ServeHTTP(w, r)
			return
		}
		// 3. Nicht angemeldet: API bekommt JSON-Fehler, alles andere die Eingabeseite.
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusUnauthorized, errBody("Zugangstoken erforderlich"))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(loginPage))
	})
}

// loginPage ist die kleine Eingabeseite (ohne Skripte, Formular per GET auf "/").
const loginPage = `<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetzScanner – Zugang</title>
<style>body{font-family:system-ui,sans-serif;background:#14161a;color:#e6e6e6;display:grid;place-items:center;min-height:100vh;margin:0}
form{background:#1d2026;padding:24px;border-radius:8px;max-width:340px}
input,button{font:inherit;padding:8px;margin-top:8px;width:100%;box-sizing:border-box}</style></head>
<body><form method="get" action="/"><h1 style="font-size:1.2rem">NetzScanner</h1>
<p>Zugangstoken eingeben (steht in der Konsole, wo der Scanner gestartet wurde).</p>
<input type="password" name="token" autocomplete="off" autofocus required>
<button type="submit">Anmelden</button></form></body></html>`
