package scan

import "testing"

// TestIPPSerial prueft das Herausloesen der Seriennummer aus der IEEE-1284-Geraete-ID.
func TestIPPSerial(t *testing.T) {
	cases := map[string]string{
		"MFG:A;MDL:B;SN:12345;CMD:PCL;": "12345",
		"MFG:A;SERN:XY-9;":              "XY-9",
		"mfg:A; sn : 77 ;":              "77",
		"MFG:A;MDL:B;":                  "",
		"":                              "",
		"kaputt ohne Doppelpunkt;SN":    "",
	}
	for in, want := range cases {
		if got := ippSerial(in); got != want {
			t.Errorf("ippSerial(%q) = %q, erwartet %q", in, got, want)
		}
	}
}

// TestDescribeIPPSerial prueft, dass die Seriennummer in der IPP-Zeile erscheint.
func TestDescribeIPPSerial(t *testing.T) {
	a := map[string][]ippValue{"printer-device-id": {{tag: 0x41, text: "MFG:A;SN:555;"}}}
	if got := describeIPP(a); got != "IPP: Seriennr. 555" {
		t.Errorf("describeIPP = %q", got)
	}
}
