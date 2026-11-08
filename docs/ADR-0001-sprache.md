# ADR-0001: Programmiersprache

**Entscheidung:** Go, mit eingebetteter Web-UI (Browser).

## Anforderungen
Linux/Windows/macOS + ARM, einfache Verteilung, viel Parallelität (Scans), Netzwerkprotokolle (SNMP, SSH, LDAP, SMB), eigene Auslese-Tools.

## Vergleich (fachliche Einschätzung, nicht gemessen)
| | Go | Rust | Python |
|---|---|---|---|
| Eine Datei ohne Installation | ✅ | ✅ | ❌ (Interpreter/PyInstaller) |
| Cross-Compile inkl. ARM | ✅ trivial (`GOOS/GOARCH`) | ⚠️ aufwendiger | ❌ |
| Nebenläufigkeit für Scans | ✅ Goroutinen | ✅ | ⚠️ |
| Libs SNMP/SSH/LDAP | ✅ Pure-Go verfügbar | ⚠️ teils jünger | ✅ |
| Lernkurve/Wartung | ✅ niedrig | ⚠️ hoch | ✅ |

## Folgen
- Kein CGO → reproduzierbare Cross-Builds (in v0.1.0 für 7 Ziele verifiziert).
- UI als Web-App: läuft auch headless auf dem Raspberry, Bedienung vom PC-Browser.
- Raw-Sockets (ARP/ICMP) brauchen Rechte → TCP-Connect-Fallback Pflicht.
- Nachteil: Native Desktop-Fenster nur über Browser/Webview (bei Bedarf später).
