package logintest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Aus dem DN wird der DNS-Domaenenname; ohne DC-Teile bleibt er leer.
func TestDomainFromDN(t *testing.T) {
	cases := map[string]string{
		"DC=firma,DC=local":   "firma.local",
		"dc=example, dc=com":  "example.com",
		"o=firma":             "",
		"":                    "",
		"OU=x,DC=a,DC=b,DC=c": "a.b.c",
	}
	for in, want := range cases {
		if got := domainFromDN(in); got != want {
			t.Errorf("domainFromDN(%q) = %q, erwartet %q", in, got, want)
		}
	}
}

// "Invalid Credentials" heisst abgelehnt; das Passwort darf nie in der Meldung stehen.
func TestClassifyLDAPBindError(t *testing.T) {
	st, _ := classifyLDAPBindError(ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("x")), "geheim")
	if st != StatusFailed {
		t.Fatalf("erwartet failed, bekam %v", st)
	}
	st, msg := classifyLDAPBindError(errors.New("dial tcp: refused geheim"), "geheim")
	if st != StatusUnavailable || strings.Contains(msg, "geheim") {
		t.Fatalf("unerwartet: %v %q", st, msg)
	}
}

// Leeres Passwort oder Benutzer: nichts wird gesendet (kein anonymer Bind als "ok").
func TestLDAP_EmptyCredentialsNotSent(t *testing.T) {
	for _, c := range [][2]string{{"", "pw"}, {"user", ""}} {
		r := LDAP(context.Background(), "127.0.0.1", 389, c[0], c[1], "", false)
		if r.Status != StatusUnavailable {
			t.Fatalf("erwartet unavailable, bekam %+v", r)
		}
	}
}

// Ohne erreichbaren Dienst (Loopback, Port zu) kommt "nicht testbar", nie "ok".
func TestLDAP_ClosedPortUnavailable(t *testing.T) {
	for _, port := range []int{389, 636} {
		r := LDAP(context.Background(), "127.0.0.1", port, "user", "pw", "", false)
		if r.Status == StatusOK || r.Method != MethodLDAP || r.Port != port {
			t.Fatalf("unerwartet: %+v", r)
		}
	}
}

// Fingerabdruck noch nicht bestaetigt -> "confirm" mit Fingerabdruck, ohne Passwort.
func TestLDAPConnectError_Confirm(t *testing.T) {
	tr := &ldapTrust{needConfirm: true, seen: "AB:CD"}
	r := ldapConnectError(Result{}, errNeedConfirm, tr, "pw")
	if r.Status != StatusConfirm || r.Fingerprint != "AB:CD" {
		t.Fatalf("unerwartet: %+v", r)
	}
	r = ldapConnectError(Result{}, errPlainNeedsConfirm, &ldapTrust{}, "pw")
	if r.Status != StatusConfirm || r.Scheme != SchemePlain || r.Fingerprint != "" {
		t.Fatalf("unerwartet: %+v", r)
	}
}
