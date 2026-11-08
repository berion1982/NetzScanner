package scan

import (
	"net"
	"strings"
	"time"
)

// httpPorts: hier fragen wir per HEAD den "Server"-Header ab.
var httpPorts = map[int]bool{80: true, 631: true, 5000: true, 8000: true, 8008: true, 8080: true, 8081: true, 8888: true}

// grabBanner liest (kurz) einen Hinweis auf den Dienst. Banner kommen aus dem
// Netz und sind NICHT vertrauenswuerdig: nur druckbare ASCII-Zeichen, begrenzte Laenge.
func grabBanner(conn net.Conn, port int, wait time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(wait))
	if httpPorts[port] {
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	text := string(buf[:n])
	if httpPorts[port] {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return sanitize(strings.TrimSpace(line[7:]))
			}
		}
		return ""
	}
	if i := strings.IndexAny(text, "\r\n"); i >= 0 {
		text = text[:i]
	}
	return sanitize(text)
}

// sanitize entfernt Steuer- und Nicht-ASCII-Zeichen und kuerzt auf 120 Zeichen.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
		if b.Len() >= 120 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}
