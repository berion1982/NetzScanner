package scan

import (
	"context"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// Validate: v2c braucht Community, v3 einen Benutzer und sinnvolle Protokoll-/Passphrase-Kombinationen.
func TestSNMPCredsValidate(t *testing.T) {
	cases := []struct {
		name string
		c    SNMPCreds
		ok   bool
	}{
		{"v2c ok", SNMPCreds{Community: "public"}, true},
		{"v2c ohne Community", SNMPCreds{}, false},
		{"v3 noAuthNoPriv", SNMPCreds{User: "u"}, true},
		{"v3 authNoPriv", SNMPCreds{User: "u", AuthProto: "SHA256", AuthPass: "passwort123"}, true},
		{"v3 authPriv", SNMPCreds{User: "u", AuthProto: "SHA", AuthPass: "passwort123", PrivProto: "AES", PrivPass: "passwort456"}, true},
		{"Auth-Passphrase zu kurz", SNMPCreds{User: "u", AuthProto: "SHA", AuthPass: "kurz"}, false},
		{"Priv ohne Auth", SNMPCreds{User: "u", PrivProto: "AES", PrivPass: "passwort456"}, false},
		{"Priv-Passphrase zu kurz", SNMPCreds{User: "u", AuthProto: "SHA", AuthPass: "passwort123", PrivProto: "AES", PrivPass: "x"}, false},
		{"unbekanntes Auth-Protokoll", SNMPCreds{User: "u", AuthProto: "XYZ", AuthPass: "passwort123"}, false},
		{"unbekanntes Priv-Protokoll", SNMPCreds{User: "u", AuthProto: "SHA", AuthPass: "passwort123", PrivProto: "XYZ", PrivPass: "passwort456"}, false},
	}
	for _, tc := range cases {
		if err := tc.c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: Fehler=%v, erwartet ok=%v", tc.name, err, tc.ok)
		}
	}
}

// newSNMP setzt Version, Sicherheitsstufe und Protokolle passend zu den Zugangsdaten.
func TestNewSNMP(t *testing.T) {
	ctx := context.Background()
	if g := newSNMP(ctx, "192.0.2.1", SNMPCreds{Community: "c"}); g.Version != gosnmp.Version2c || g.Community != "c" {
		t.Errorf("v2c falsch: %+v", g)
	}
	g := newSNMP(ctx, "192.0.2.1", SNMPCreds{User: "u", AuthProto: "SHA256", AuthPass: "passwort123", PrivProto: "AES256", PrivPass: "passwort456"})
	usm, _ := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if g.Version != gosnmp.Version3 || g.MsgFlags != gosnmp.AuthPriv || usm == nil ||
		usm.AuthenticationProtocol != gosnmp.SHA256 || usm.PrivacyProtocol != gosnmp.AES256 || usm.UserName != "u" {
		t.Errorf("v3 authPriv falsch: %+v", g)
	}
	if g := newSNMP(ctx, "192.0.2.1", SNMPCreds{User: "u", AuthProto: "MD5", AuthPass: "passwort123"}); g.MsgFlags != gosnmp.AuthNoPriv {
		t.Errorf("authNoPriv falsch: %v", g.MsgFlags)
	}
	if g := newSNMP(ctx, "192.0.2.1", SNMPCreds{User: "u"}); g.MsgFlags != gosnmp.NoAuthNoPriv {
		t.Errorf("noAuthNoPriv falsch: %v", g.MsgFlags)
	}
}
