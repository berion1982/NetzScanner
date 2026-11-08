package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
)

// readCert liest das TLS-Zertifikat eines Ports und fasst es zusammen (I-004).
// Die Pruefung ist ABSICHTLICH aus (InsecureSkipVerify): Geraete nutzen meist
// selbst signierte Zertifikate; wir lesen nur und senden keine Daten.
// Liefert nil, wenn kein TLS-Handshake moeglich ist.
func readCert(ctx context.Context, ip string, port int) *model.Cert {
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return summarizeCert(certs[0], time.Now())
}

// summarizeCert macht aus einem Zertifikat die Kurzinfo. Texte stammen aus dem
// Netz und werden deshalb mit sanitize bereinigt.
func summarizeCert(c *x509.Certificate, now time.Time) *model.Cert {
	subject := sanitize(c.Subject.CommonName)
	if subject == "" && len(c.DNSNames) > 0 {
		subject = sanitize(c.DNSNames[0])
	}
	days := int(c.NotAfter.Sub(now).Hours() / 24)
	if c.NotAfter.Before(now) {
		days = -int(now.Sub(c.NotAfter).Hours() / 24) // abgelaufen: negative Tage
	}
	return &model.Cert{
		Subject:    subject,
		Issuer:     sanitize(c.Issuer.CommonName),
		NotAfter:   c.NotAfter.UTC().Format("2006-01-02"),
		DaysLeft:   days,
		Expired:    c.NotAfter.Before(now),
		SelfSigned: c.Subject.String() == c.Issuer.String(),
	}
}
