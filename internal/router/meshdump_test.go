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

// TestDumpMesh: Fake-Box liefert Pfad mit sid und ein JSON; Ausgabe enthält JSON, aber nicht die sid.
func TestDumpMesh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Write([]byte(`<s:Envelope xmlns:s="x"><s:Body><u:X_AVM-DE_GetMeshListPathResponse xmlns:u="y">` +
				`<NewX_AVM-DE_MeshListPath>http://fritz.box:49000/meshlist.lua?sid=GEHEIM</NewX_AVM-DE_MeshListPath>` +
				`</u:X_AVM-DE_GetMeshListPathResponse></s:Body></s:Envelope>`))
			return
		}
		w.Write([]byte(`{"nodes":[]}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	tr064PortOverride = u.Port()
	defer func() { tr064PortOverride = "" }()
	var buf bytes.Buffer
	if err := DumpMesh(context.Background(), "127.0.0.1", "u", "p", &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `{"nodes":[]}`) || strings.Contains(out, "GEHEIM") {
		t.Fatalf("unerwartete Ausgabe: %s", out)
	}
}
