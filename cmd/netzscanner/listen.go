// Adresse und Port des Webservers (I-088, Mehrbenutzer-Betrieb).
//
// Auf einem Terminalserver teilen sich alle angemeldeten Benutzer dieselbe
// Loopback-Adresse 127.0.0.1. Ein fester Port 8484 wuerde deshalb nur dem ersten
// Benutzer gehoeren, und jeder andere Benutzer koennte dessen Oberflaeche
// aufrufen. Darum gilt ohne ausdrueckliches --listen:
//   - bevorzugt 127.0.0.1:8484, ist er belegt, ein freier Port (127.0.0.1:0),
//   - ein zufaelliges Zugangstoken, das nur der eigene Browser-Aufruf kennt.
package main

import (
	"net"

	"github.com/berion1982/netzscanner/internal/web"
)

// defaultListen ist die bevorzugte Adresse ohne --listen.
const defaultListen = "127.0.0.1:8484"

// openListener oeffnet den Server-Port.
//   - explicit (Nutzer gab --listen an): genau diese Adresse, Fehler wenn belegt.
//   - sonst: erst defaultListen, bei Belegung ein freier Port auf 127.0.0.1.
func openListener(explicit bool, addr string) (net.Listener, error) {
	if explicit {
		return net.Listen("tcp", addr)
	}
	if ln, err := net.Listen("tcp", defaultListen); err == nil {
		return ln, nil
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

// autoToken: ohne ausdrueckliches --listen (lokaler Normalbetrieb) wird auch bei
// Loopback ein Token erzeugt, damit andere Benutzer desselben Rechners die
// Oberflaeche nicht aufrufen koennen. --no-token schaltet das ab.
func autoToken(explicitListen, disable bool, listen string) bool {
	return !explicitListen && !disable && web.IsLoopbackListen(listen)
}
