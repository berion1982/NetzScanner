package router

// Router-Info und WLAN der FRITZ!Box per TR-064 (I-055).
//
// Gelesen werden nur harmlose Betriebsdaten: Modell, Firmware, Laufzeit, WAN-Status,
// DHCP-Bereich, WLAN-Einstellungen (SSID, Kanal, Standard, Verschluesselungsart) und die
// verbundenen WLAN-Clients mit Signal. NIEMALS gelesen wird der WLAN-Schluessel
// (Aktion GetSecurityKeys) und es werden keine Einstellungen veraendert (nur Get*-Aktionen).
//
// Ehrlich zur Technik: Welche Dienste und Felder eine Box liefert, haengt von Modell und
// FRITZ!OS ab; fehlende Teile werden uebersprungen und in Notes vermerkt. Gegen eine echte
// Box ist das in der Entwicklung nicht geprueft (nur gegen einen Test-Server).

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// Grenzen
const (
	maxWLANs       = 4   // WLANConfiguration:1 bis :4 (2,4 GHz, 5 GHz, Gast ...)
	maxWLANClients = 128 // je WLAN
)

// Info sind die Netzwerkdaten des Routers (ohne Zugangsdaten und ohne WLAN-Schluessel).
type Info struct {
	Model       string   `json:"model,omitempty"`
	Firmware    string   `json:"firmware,omitempty"`
	UptimeSec   int64    `json:"uptimeSec,omitempty"`
	WANStatus   string   `json:"wanStatus,omitempty"` // z. B. "Connected"
	WANAccess   string   `json:"wanAccess,omitempty"` // z. B. "DSL", "Ethernet"
	WANUptime   int64    `json:"wanUptimeSec,omitempty"`
	ExternalIP  string   `json:"externalIP,omitempty"` // nur Anzeige, nie in Dateien
	DownKbps    int64    `json:"downKbps,omitempty"`   // maximale Leitungsrate
	UpKbps      int64    `json:"upKbps,omitempty"`
	DHCPEnabled bool     `json:"dhcpEnabled"`
	DHCPFrom    string   `json:"dhcpFrom,omitempty"`
	DHCPTo      string   `json:"dhcpTo,omitempty"`
	Subnet      string   `json:"subnet,omitempty"`
	Gateway     string   `json:"gateway,omitempty"`
	DNS         string   `json:"dns,omitempty"`
	WLANs       []WLAN   `json:"wlans"`
	Notes       []string `json:"notes,omitempty"` // was nicht gelesen werden konnte (ehrlich anzeigen)
}

// WLAN ist ein WLAN-Netz (Funknetz) der Box.
type WLAN struct {
	Index      int          `json:"index"` // 1..4 (WLANConfiguration:n)
	SSID       string       `json:"ssid"`
	Enabled    bool         `json:"enabled"`
	Channel    int          `json:"channel,omitempty"`
	Band       string       `json:"band,omitempty"` // "2,4 GHz" / "5 GHz" (aus dem Kanal abgeleitet), sonst leer
	Standard   string       `json:"standard,omitempty"`
	Encryption string       `json:"encryption,omitempty"`
	Open       bool         `json:"open"` // true = keine Verschluesselung
	Clients    []WLANClient `json:"clients"`
}

// WLANClient ist ein am WLAN angemeldetes Geraet.
type WLANClient struct {
	MAC    string `json:"mac"`
	IP     string `json:"ip,omitempty"`
	Signal int    `json:"signal,omitempty"` // laut FRITZ!Box in Prozent (0-100), 0 = unbekannt
	Speed  int    `json:"speed,omitempty"`  // Mbit/s, 0 = unbekannt
}

var (
	svcDeviceInfo = service{"/upnp/control/deviceinfo", "urn:dslforum-org:service:DeviceInfo:1"}
	svcWANIP      = service{"/upnp/control/wanipconnection1", "urn:dslforum-org:service:WANIPConnection:1"}
	svcWANPPP     = service{"/upnp/control/wanpppconn1", "urn:dslforum-org:service:WANPPPConnection:1"}
	svcWANCommon  = service{"/upnp/control/wancommonifconfig1", "urn:dslforum-org:service:WANCommonInterfaceConfig:1"}
	svcLAN        = service{"/upnp/control/lanhostconfigmgm", "urn:dslforum-org:service:LANHostConfigManagement:1"}
)

// svcWLAN liefert den Dienst fuer WLANConfiguration:n (n = 1..4).
func svcWLAN(n int) service {
	return service{"/upnp/control/wlanconfig" + strconv.Itoa(n), "urn:dslforum-org:service:WLANConfiguration:" + strconv.Itoa(n)}
}

// readInfo liest alle Netzwerkdaten. Jeder Teil ist unabhaengig; Fehler -> Hinweis in Notes.
func (c *client) readInfo(ctx context.Context) Info {
	info := Info{WLANs: []WLAN{}}
	note := func(what string, err error) {
		reason := "nicht lesbar"
		if errors.Is(err, errUnavailable) {
			reason = "an dieser Box nicht verfügbar"
		}
		info.Notes = append(info.Notes, what+": "+reason)
	}

	if r, err := c.call(ctx, svcDeviceInfo, "GetInfo", ""); err == nil {
		info.Model = clean(firstNonEmpty(r["NewModelName"], r["NewDescription"]), 80)
		info.Firmware = clean(r["NewSoftwareVersion"], 40)
		info.UptimeSec = atoi64(r["NewUpTime"])
	} else {
		note("Geräteinfo", err)
	}

	// WAN: erst IP-Anschluss, sonst PPP (DSL mit PPPoE).
	r, err := c.call(ctx, svcWANIP, "GetInfo", "")
	if err != nil {
		r, err = c.call(ctx, svcWANPPP, "GetInfo", "")
	}
	if err == nil {
		info.WANStatus = clean(r["NewConnectionStatus"], 30)
		info.WANUptime = atoi64(r["NewUptime"])
		info.ExternalIP = clean(r["NewExternalIPAddress"], 45)
	} else {
		note("WAN-Status", err)
	}
	if r, err := c.call(ctx, svcWANCommon, "GetCommonLinkProperties", ""); err == nil {
		info.WANAccess = clean(r["NewWANAccessType"], 20)
		info.DownKbps = atoi64(r["NewLayer1DownstreamMaxBitRate"]) / 1000
		info.UpKbps = atoi64(r["NewLayer1UpstreamMaxBitRate"]) / 1000
	} else {
		note("Leitungsdaten", err)
	}
	if r, err := c.call(ctx, svcLAN, "GetInfo", ""); err == nil {
		info.DHCPEnabled = r["NewDHCPServerEnable"] == "1"
		info.DHCPFrom, info.DHCPTo = clean(r["NewMinAddress"], 45), clean(r["NewMaxAddress"], 45)
		info.Subnet, info.Gateway = clean(r["NewSubnetMask"], 45), clean(r["NewIPRouters"], 45)
		info.DNS = clean(r["NewDNSServers"], 100)
	} else {
		note("DHCP/Heimnetz", err)
	}

	for n := 1; n <= maxWLANs; n++ {
		w, err := c.readWLAN(ctx, n)
		if errors.Is(err, errUnavailable) {
			break // keine weiteren WLAN-Schnittstellen
		}
		if err != nil {
			note("WLAN "+strconv.Itoa(n), err)
			continue
		}
		info.WLANs = append(info.WLANs, w)
	}
	return info
}

// readWLAN liest eine WLAN-Schnittstelle samt angemeldeter Clients. Es wird nur GetInfo,
// GetTotalAssociations und GetGenericAssociatedDeviceInfo benutzt - nie GetSecurityKeys.
func (c *client) readWLAN(ctx context.Context, n int) (WLAN, error) {
	svc := svcWLAN(n)
	r, err := c.call(ctx, svc, "GetInfo", "")
	if err != nil {
		return WLAN{}, err
	}
	w := WLAN{Index: n, SSID: clean(r["NewSSID"], 32), Enabled: r["NewEnable"] == "1", Standard: clean(r["NewStandard"], 20),
		Channel: int(atoi64(r["NewChannel"])), Clients: []WLANClient{}}
	w.Band = bandFromChannel(w.Channel)
	w.Encryption, w.Open = encryption(r["NewBeaconType"])
	if !w.Enabled {
		return w, nil
	}
	t, err := c.call(ctx, svc, "GetTotalAssociations", "")
	if err != nil {
		return w, nil // Clients nicht lesbar, WLAN selbst ist da
	}
	total := int(atoi64(t["NewTotalAssociations"]))
	if total > maxWLANClients {
		total = maxWLANClients
	}
	for i := 0; i < total; i++ {
		d, err := c.call(ctx, svc, "GetGenericAssociatedDeviceInfo", "<NewAssociatedDeviceIndex>"+strconv.Itoa(i)+"</NewAssociatedDeviceIndex>")
		if errors.Is(err, ErrAuth) {
			return w, err
		}
		if err != nil {
			continue
		}
		w.Clients = append(w.Clients, WLANClient{
			MAC: clean(d["NewAssociatedDeviceMACAddress"], 17), IP: clean(d["NewAssociatedDeviceIPAddress"], 45),
			Signal: int(atoi64(d["NewX_AVM-DE_SignalStrength"])), Speed: int(atoi64(d["NewX_AVM-DE_Speed"])),
		})
	}
	return w, nil
}

// bandFromChannel leitet das Frequenzband aus dem Kanal ab (1-14 = 2,4 GHz; ab 32 = 5 GHz; sonst unbekannt).
func bandFromChannel(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return "2,4 GHz"
	case ch >= 32:
		return "5 GHz"
	}
	return ""
}

// encryption uebersetzt den TR-064-"BeaconType" in Klartext; der zweite Wert ist true bei "offen".
func encryption(beacon string) (string, bool) {
	switch strings.TrimSpace(beacon) {
	case "None":
		return "keine (offenes WLAN)", true
	case "Basic":
		return "WEP (unsicher)", false
	case "WPA":
		return "WPA", false
	case "11i":
		return "WPA2", false
	case "WPAand11i":
		return "WPA/WPA2", false
	case "":
		return "", false
	}
	return clean(beacon, 30), false // z. B. neuere Werte (WPA3): Rohwert anzeigen
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
