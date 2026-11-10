package logintest

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// 401 vom Server heisst: Anmeldung abgelehnt.
func TestClassifyWinRMError_Rejected(t *testing.T) {
	st, msg := classifyWinRMError(errors.New("http error 401: Unauthorized"), "geheim")
	if st != StatusFailed || msg == "" {
		t.Fatalf("erwartet failed, bekam %v %q", st, msg)
	}
}

// Andere Fehler sind "nicht testbar"; das Passwort darf nie in der Meldung stehen.
func TestClassifyWinRMError_UnavailableHidesPassword(t *testing.T) {
	st, msg := classifyWinRMError(errors.New("dial tcp: refused geheim"), "geheim")
	if st != StatusUnavailable {
		t.Fatalf("erwartet unavailable, bekam %v", st)
	}
	if strings.Contains(msg, "geheim") {
		t.Fatalf("Passwort in Meldung: %q", msg)
	}
}

// Ohne erreichbaren WinRM-Dienst (Loopback, Port zu) kommt "nicht testbar", nie "ok".
func TestWinRM_ClosedPortUnavailable(t *testing.T) {
	r := WinRM(context.Background(), "127.0.0.1", "user", "pw")
	if r.Status == StatusOK || r.Port != WinRMPort || r.Method != MethodWinRM {
		t.Fatalf("unerwartet: %+v", r)
	}
}
