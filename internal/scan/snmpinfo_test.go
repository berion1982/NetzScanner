package scan

import "testing"

// Laufzeit-Anzeige aus Hundertstel Sekunden.
func TestFormatTicks(t *testing.T) {
	cases := map[int]string{
		0:                               "0 Min",
		6000:                            "1 Min",
		360000 + 6000:                   "1 Std 1 Min",
		(3*86400 + 4*3600 + 5*60) * 100: "3 Tage 4 Std 5 Min",
	}
	for in, want := range cases {
		if got := formatTicks(in); got != want {
			t.Errorf("formatTicks(%d) = %q, erwartet %q", in, got, want)
		}
	}
}

// MAC aus Bytes: nur 6 Bytes, nicht lauter Nullen.
func TestFormatMACBytes(t *testing.T) {
	if got := formatMACBytes([]byte{0xAA, 0xbb, 1, 2, 3, 4}); got != "aa:bb:01:02:03:04" {
		t.Errorf("MAC = %q", got)
	}
	if formatMACBytes(nil) != "" || formatMACBytes(make([]byte, 6)) != "" || formatMACBytes([]byte{1, 2}) != "" {
		t.Error("leer, nur Nullen und falsche Laenge muessen leer ergeben")
	}
}

func TestFormatMbit(t *testing.T) {
	for in, want := range map[int]string{10: "10 Mbit/s", 100: "100 Mbit/s", 1000: "1 Gbit/s", 2500: "2.5 Gbit/s", 10000: "10 Gbit/s"} {
		if got := formatMbit(in); got != want {
			t.Errorf("formatMbit(%d) = %q, erwartet %q", in, got, want)
		}
	}
}

// Schnittstellenzeilen: nach Index sortiert, Loopback uebersprungen, fehlende Werte weggelassen.
func TestIfaceFields(t *testing.T) {
	names := map[string]string{"10": "Gi1/0/2", "2": "Gi1/0/1", "1": "lo", "3": ""}
	status := map[string]int{"2": 1, "10": 2}
	speed := map[string]int{"2": 1000}
	macs := map[string]string{"2": "aa:bb:cc:00:11:22"}
	got := ifaceFields(names, status, speed, macs)
	if len(got) != 2 {
		t.Fatalf("erwartet 2 Zeilen, bekam %d: %v", len(got), got)
	}
	if got[0].Name != "Schnittstelle Gi1/0/1" || got[0].Value != "aktiv, aa:bb:cc:00:11:22, 1 Gbit/s" {
		t.Errorf("Zeile 1 = %+v", got[0])
	}
	if got[1].Name != "Schnittstelle Gi1/0/2" || got[1].Value != "inaktiv" {
		t.Errorf("Zeile 2 = %+v", got[1])
	}
}

// Begrenzung der Zeilenzahl.
func TestIfaceFieldsLimit(t *testing.T) {
	names := map[string]string{}
	for i := 1; i <= maxInfoIfaces+10; i++ {
		names[itoa(i)] = "eth" + itoa(i)
	}
	if got := ifaceFields(names, nil, nil, nil); len(got) != maxInfoIfaces {
		t.Errorf("erwartet %d Zeilen, bekam %d", maxInfoIfaces, len(got))
	}
}

// Erster nicht leerer Wert nach kleinstem Index.
func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty(map[string]string{"3": "C", "2": " ", "5": "E", "4": "D"}); got != "C" {
		t.Errorf("firstNonEmpty = %q", got)
	}
	if firstNonEmpty(nil) != "" {
		t.Error("leere Tabelle muss leer ergeben")
	}
}

func itoa(i int) string { return string(rune('0'+i/10)) + string(rune('0'+i%10)) }
