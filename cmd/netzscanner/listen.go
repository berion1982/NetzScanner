// Adresse und Port des Webservers (I-088/I-089, Mehrbenutzer-Betrieb).
//
// Auf einem Terminalserver teilen sich alle angemeldeten Benutzer dieselbe
// Loopback-Adresse 127.0.0.1. Ein fester Port wuerde deshalb nur dem ersten
// Benutzer gehoeren und jeder koennte auf der Adresse eines anderen landen.
// Darum gilt ohne ausdrueckliches --listen:
//   - IMMER ein freier, vom System gewaehlter Port auf 127.0.0.1 (kein fester Standardport):
//     "127.0.0.1" ohne Port oder ein geratener Port laeuft ins Leere,
//   - ein zufaelliges Zugangstoken als Pfad im Link ("http://127.0.0.1:PORT/TOKEN"),
//     ohne das der Server gar nicht antwortet (404 ohne Inhalt).
//
// Wer eine feste Adresse braucht (z. B. Raspberry, Skripte), gibt --listen an;
// dann gilt das bisherige Verhalten.
package main

import (
	"net"

	"github.com/berion1982/netzscanner/internal/web"
)

// openListener oeffnet den Server-Port.
//   - explicit (Nutzer gab --listen an): genau diese Adresse, Fehler wenn belegt.
//   - sonst: ein freier Port auf 127.0.0.1 (Port 0 = das System waehlt).
func openListener(explicit bool, addr string) (net.Listener, error) {
	if explicit {
		return net.Listen("tcp", addr)
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

// autoToken: ohne ausdrueckliches --listen (lokaler Normalbetrieb) wird auch bei
// Loopback ein Token erzeugt und der Server antwortet nur mit diesem Token im Link.
// --no-token schaltet das ab.
func autoToken(explicitListen, disable bool, listen string) bool {
	return !explicitListen && !disable && web.IsLoopbackListen(listen)
}
