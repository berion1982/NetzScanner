package logintest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hirochachacha/go-smb2"
)

// Benutzername: nur "DOMAENE\benutzer" wird getrennt, alles andere bleibt als Konto.
func TestSplitSMBUser(t *testing.T) {
	cases := []struct{ in, domain, account string }{
		{`FIRMA\anna`, "FIRMA", "anna"},
		{`  FIRMA\anna `, "FIRMA", "anna"},
		{"anna", "", "anna"},
		{"anna@firma.example", "", "anna@firma.example"},
		{`FIRMA\`, "", `FIRMA\`}, // kein Konto hinter dem Backslash: unveraendert lassen
	}
	for _, c := range cases {
		d, a := splitSMBUser(c.in)
		if d != c.domain || a != c.account {
			t.Errorf("splitSMBUser(%q) = %q,%q; erwartet %q,%q", c.in, d, a, c.domain, c.account)
		}
	}
}

// Fehler des Servers werden richtig eingeordnet; alles Unbekannte ist "nicht testbar".
func TestClassifySMBError(t *testing.T) {
	cases := []struct {
		err  error
		want Status
	}{
		{&smb2.ResponseError{Code: ntLogonFailure}, StatusFailed},
		{&smb2.ResponseError{Code: ntWrongPassword}, StatusFailed},
		{&smb2.ResponseError{Code: ntNoSuchUser}, StatusFailed},
		{&smb2.ResponseError{Code: ntAccountLockedOut}, StatusFailed},
		{&smb2.ResponseError{Code: ntAccountDisabled}, StatusFailed},
		{&smb2.ResponseError{Code: ntPasswordExpired}, StatusFailed},
		{&smb2.ResponseError{Code: ntAccountRestricted}, StatusFailed},
		{fmt.Errorf("verpackt: %w", &smb2.ResponseError{Code: ntLogonFailure}), StatusFailed},
		{&smb2.ResponseError{Code: 0xC00000BB}, StatusUnavailable}, // NOT_SUPPORTED
		{&smb2.InvalidResponseError{Message: "guest account doesn't support signing"}, StatusFailed},
		{errors.New("i/o timeout"), StatusUnavailable},
	}
	for _, c := range cases {
		if got, _ := classifySMBError(c.err, "geheim"); got != c.want {
			t.Errorf("classifySMBError(%v) = %s; erwartet %s", c.err, got, c.want)
		}
	}
}

// Das Passwort darf nie in der Meldung stehen.
func TestClassifySMBErrorHidesPassword(t *testing.T) {
	_, msg := classifySMBError(errors.New("fehler mit geheim123 drin"), "geheim123")
	if strings.Contains(msg, "geheim123") {
		t.Errorf("Passwort in Meldung: %q", msg)
	}
}

// Freigabenamen: bereinigt, sortiert, begrenzt; leere Listen ergeben keine Felder.
func TestShareFields(t *testing.T) {
	if shareFields(nil) != nil || shareFields([]string{"", "  "}) != nil {
		t.Error("leere Liste muss nil ergeben")
	}
	f := shareFields([]string{"Daten", "ADMIN$", "IPC$", "x\x00y"})
	if len(f) != 1 || f[0].Name != "Freigaben" || f[0].Value != "ADMIN$, Daten, IPC$, xy" {
		t.Errorf("unerwartet: %+v", f)
	}
	var many []string
	for i := 0; i < maxSMBShares+5; i++ {
		many = append(many, fmt.Sprintf("s%02d", i))
	}
	if v := shareFields(many)[0].Value; !strings.HasSuffix(v, "(+5 weitere)") {
		t.Errorf("Begrenzung fehlt: %q", v)
	}
}

// Ohne Passwort/Benutzer wird nichts gesendet (auch kein Verbindungsaufbau).
func TestSMBNeedsCredentials(t *testing.T) {
	for _, c := range [][2]string{{"anna", ""}, {"", "pw"}} {
		r := SMB(context.Background(), "192.0.2.1", c[0], c[1])
		if r.Status != StatusUnavailable || r.Method != MethodSMB || r.Port != SMBPort {
			t.Errorf("unerwartet: %+v", r)
		}
	}
}
