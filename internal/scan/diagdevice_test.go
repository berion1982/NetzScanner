package scan

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
)

// Die Befehle haben feste Argumente; die IP steht immer als letztes Argument und nie als Option.
func TestDiagCommands(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows", "freebsd"} {
		c := pingCommand(goos, "192.0.2.7")
		if c.name != "ping" || c.args[len(c.args)-1] != "192.0.2.7" {
			t.Errorf("%s: ping unerwartet: %+v", goos, c)
		}
		cmds := traceCommands(goos, "192.0.2.7")
		if len(cmds) == 0 {
			t.Fatalf("%s: kein Traceroute-Befehl", goos)
		}
		for _, tc := range cmds {
			if tc.args[len(tc.args)-1] != "192.0.2.7" {
				t.Errorf("%s: IP nicht letztes Argument: %+v", goos, tc)
			}
		}
	}
	if traceCommands("windows", "192.0.2.7")[0].name != "tracert" {
		t.Error("Windows muss tracert nutzen")
	}
}

// Gespeicherte Daten: wichtige Felder erscheinen, leere werden weggelassen.
func TestStoredHostLines(t *testing.T) {
	h := model.Host{IP: "192.0.2.7", Name: "gerät", NameSource: "mdns", MAC: "AA:BB:CC:00:11:22", Vendor: "Beispiel AG",
		Category: "iot", Ports: []model.Port{
			{Number: 443, Service: "https", Cert: &model.Cert{Subject: "x", Issuer: "y", NotAfter: "2030-01-01", SelfSigned: true}},
			{Number: 22, Service: "ssh", Banner: "SSH-2.0-Test"},
		}}
	text := strings.Join(storedHostLines(h), "\n")
	for _, want := range []string{"gerät", "mdns", "AA:BB:CC:00:11:22", "Beispiel AG", "Vermutung des Scans",
		"Port 443", "selbst signiert: true", `banner="SSH-2.0-Test"`} {
		if !strings.Contains(text, want) {
			t.Errorf("fehlt %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Standort") || strings.Contains(text, "Uplink") {
		t.Errorf("leere Felder duerfen nicht erscheinen:\n%s", text)
	}
	if !strings.Contains(strings.Join(storedHostLines(model.Host{IP: "192.0.2.8"}), "\n"), "keine gefunden") {
		t.Error("Hinweis auf fehlende Ports fehlt")
	}
}

func TestNeedsRightsHint(t *testing.T) {
	if !needsRightsHint("traceroute: socket: Operation not permitted") || !needsRightsHint("ping: Permission denied") {
		t.Error("Rechte-Hinweis nicht erkannt")
	}
	if needsRightsHint("1  192.0.2.1  0.4 ms") {
		t.Error("falscher Rechte-Hinweis")
	}
}

func TestRTTSummary(t *testing.T) {
	if got := rttSummary(nil, 4); got != "0 von 4 Antworten" {
		t.Errorf("unerwartet: %q", got)
	}
	got := rttSummary([]time.Duration{2 * time.Millisecond, 4 * time.Millisecond}, 2)
	if !strings.HasPrefix(got, "2 von 4 Antworten") || !strings.Contains(got, "2ms / 3ms / 4ms") {
		t.Errorf("unerwartet: %q", got)
	}
}

// Die Ausgabe eines Systembefehls wird begrenzt, der Befehl aber nicht mit einem Schreibfehler abgebrochen.
func TestLimitedBuffer(t *testing.T) {
	b := &limitedBuffer{max: 5}
	if n, err := b.Write([]byte("abcdefgh")); n != 8 || err != nil {
		t.Errorf("Write: %d %v", n, err)
	}
	b.Write([]byte("zzz"))
	if b.String() != "abcde" {
		t.Errorf("unerwartet: %q", b.String())
	}
}

// Ein nicht vorhandener Befehl wird gemeldet (false), nichts wird ausgegeben.
func TestRunDiagCommandMissing(t *testing.T) {
	var out bytes.Buffer
	p := func(f string, a ...any) { out.WriteString(f) }
	if runDiagCommand(context.Background(), p, diagCommand{"netzscanner-gibt-es-nicht", nil}, time.Second) || out.Len() != 0 {
		t.Error("fehlender Befehl muss false liefern und nichts ausgeben")
	}
}

// Ungueltige IP: Bericht bricht sauber mit Fehlermeldung ab (kein Netzverkehr).
func TestDiagnoseDeviceInvalidIP(t *testing.T) {
	var out bytes.Buffer
	DiagnoseDevice(context.Background(), model.Host{IP: "kein-ip"}, DiagOptions{}, nil, &out)
	if !strings.Contains(out.String(), "FEHLER: keine gueltige IP-Adresse") {
		t.Errorf("unerwartet:\n%s", out.String())
	}
}
