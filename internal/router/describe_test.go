package router

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Fake-Box: tr64desc.xml mit verschachteltem Geraet und eine SCPD-Datei mit Aktionen.
func TestDescribe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/tr64desc.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<root><device><serviceList><service><serviceType>urn:dslforum-org:service:Hosts:1</serviceType><SCPDURL>/hostsSCPD.xml</SCPDURL></service></serviceList>
		<deviceList><device><serviceList><service><serviceType>urn:dslforum-org:service:LANHostConfigManagement:1</serviceType><SCPDURL>/lanSCPD.xml</SCPDURL></service></serviceList></device></deviceList></device></root>`))
	})
	mux.HandleFunc("/hostsSCPD.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<scpd><actionList><action><name>GetGenericHostEntry</name></action><action><name>X_AVM-DE_GetHostListPath</name></action><action><name>SetAddressReservation</name></action></actionList></scpd>`))
	})
	// lanSCPD.xml fehlt absichtlich -> "nicht lesbar", aber kein Abbruch
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	tr064PortOverride = u.Port()
	defer func() { tr064PortOverride = "" }()

	var out bytes.Buffer
	Describe(context.Background(), "127.0.0.1", &out)
	got := out.String()
	for _, want := range []string{"[urn:dslforum-org:service:Hosts:1]", "GetGenericHostEntry", "X_AVM-DE_GetHostListPath",
		"[urn:dslforum-org:service:LANHostConfigManagement:1]", "nicht lesbar", "SetAddressReservation  <<"} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in:\n%s", want, got)
		}
	}
}
