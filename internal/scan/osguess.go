package scan

// Betriebssystem-Vermutung (I-013) aus Daten, die der Scan ohnehin schon hat:
// SSH-Banner, HTTP-"Server"-Header und typische offene Ports. Es wird NICHTS zusaetzlich
// gesendet und kein Login versucht.
//
// Ehrlich zur Genauigkeit: Das Ergebnis ist eine VERMUTUNG. Banner koennen veraendert oder
// falsch sein, und die Versionszuordnung (z. B. OpenSSH 8.9 -> Ubuntu 22.04) gilt nur fuer
// unveraenderte Distributionspakete. Ein Geraet ohne aussagekraeftigen Banner bleibt leer.

import (
	"regexp"
	"strings"

	"github.com/berion1982/netzscanner/internal/model"
)

// ubuntuByOpenSSH ordnet die OpenSSH-Version (Major.Minor) der Ubuntu-Version zu, die sie
// ausliefert (Annahme: unveraendertes Distributionspaket).
var ubuntuByOpenSSH = map[string]string{
	"7.2": "16.04", "7.6": "18.04", "8.2": "20.04", "8.9": "22.04", "9.6": "24.04",
}

var (
	// "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" -> Version 8.9
	reOpenSSH = regexp.MustCompile(`OpenSSH_(\d+\.\d+)`)
	// "Debian-5+deb12u3" -> Debian 12
	reDebian = regexp.MustCompile(`deb(\d+)u`)
	// "Microsoft-IIS/10.0" -> 10.0
	reIIS = regexp.MustCompile(`Microsoft-IIS/(\d+\.\d+)`)
	// "Apache/2.4.52 (Ubuntu)" -> Ubuntu (Distribution in Klammern)
	reServerDistro = regexp.MustCompile(`\((Ubuntu|Debian|CentOS|Fedora|Red Hat[^)]*|FreeBSD|Win64|Win32|Unix|Raspbian)\)`)
)

// iisWindows nennt die Windows-Versionen, die zur IIS-Version passen (IIS 10.0 gibt es auf
// mehreren Windows-Versionen, deshalb bewusst unscharf).
var iisWindows = map[string]string{
	"10.0": "Windows 10/11 oder Windows Server 2016/2019/2022",
	"8.5":  "Windows 8.1 oder Windows Server 2012 R2",
	"8.0":  "Windows 8 oder Windows Server 2012",
	"7.5":  "Windows 7 oder Windows Server 2008 R2",
	"7.0":  "Windows Vista oder Windows Server 2008",
}

// GuessOS liefert eine Betriebssystem-Vermutung fuer ein Geraet oder "" (unbekannt).
// Reihenfolge: genaue Hinweise aus Bannern vor groben Hinweisen aus offenen Ports.
func GuessOS(h model.Host) string {
	for _, p := range h.Ports {
		if os := osFromBanner(p.Banner); os != "" {
			return os
		}
	}
	return osFromPorts(h.Ports)
}

// osFromBanner wertet einen einzelnen Banner aus (SSH oder HTTP-Server-Header).
func osFromBanner(b string) string {
	switch {
	case b == "":
		return ""
	case strings.HasPrefix(b, "SSH-"):
		return osFromSSH(b)
	case reIIS.MatchString(b):
		v := reIIS.FindStringSubmatch(b)[1]
		if name, ok := iisWindows[v]; ok {
			return name + " (IIS " + v + ")"
		}
		return "Windows (IIS " + v + ")"
	case strings.Contains(b, "Microsoft-HTTPAPI"):
		return "Windows (HTTP-Server)"
	}
	if m := reServerDistro.FindStringSubmatch(b); m != nil {
		switch m[1] {
		case "Win64", "Win32":
			return "Windows (Server-Header)"
		case "Unix":
			return "Linux/Unix (Server-Header)"
		}
		return m[1] + " (Server-Header)"
	}
	return ""
}

// osFromSSH wertet den SSH-Banner aus, z. B. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".
func osFromSSH(b string) string {
	lower := strings.ToLower(b)
	ver := ""
	if m := reOpenSSH.FindStringSubmatch(b); m != nil {
		ver = m[1]
	}
	switch {
	case strings.Contains(b, "OpenSSH_for_Windows"):
		return "Windows (OpenSSH, SSH-Banner)"
	case strings.Contains(lower, "raspbian"):
		return "Raspberry Pi OS / Raspbian (SSH-Banner)"
	case strings.Contains(b, "Ubuntu"):
		if u, ok := ubuntuByOpenSSH[ver]; ok {
			return "Ubuntu " + u + " (aus SSH-Version geschätzt)"
		}
		return "Ubuntu (SSH-Banner)"
	case strings.Contains(b, "Debian"):
		if m := reDebian.FindStringSubmatch(b); m != nil {
			return "Debian " + m[1] + " (SSH-Banner)"
		}
		return "Debian (SSH-Banner)"
	case strings.Contains(b, "FreeBSD"):
		return "FreeBSD (SSH-Banner)"
	case strings.Contains(b, "ROSSSH"):
		return "MikroTik RouterOS (SSH-Banner)"
	case strings.Contains(lower, "dropbear"):
		return "Linux, eingebettet (Dropbear-SSH)"
	case strings.Contains(b, "OpenSSH"):
		return "Linux/Unix (OpenSSH, Distribution unbekannt)"
	}
	return ""
}

// osFromPorts schliesst grob aus typischen Windows-/Apple-Ports. Das ist die schwaechste Quelle.
func osFromPorts(ports []model.Port) string {
	has := map[int]bool{}
	for _, p := range ports {
		has[p.Number] = true
	}
	switch {
	case has[3389] || has[135] || has[5985]:
		return "Windows (RDP/RPC/WinRM offen, Vermutung)"
	case has[62078]:
		return "iOS/iPadOS (Apple, Vermutung)"
	case has[548]:
		return "macOS (AFP offen, Vermutung)"
	}
	return ""
}
