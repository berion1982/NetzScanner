package scan

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
)

// Options steuert einen Scan.
type Options struct {
	Target      string        // z.B. "192.168.1.0/24"
	Ports       []int         // leer = DefaultPorts
	Timeout     time.Duration // Verbindungs-Timeout je Port (Standard 800ms)
	Concurrency int           // gleichzeitige Verbindungen gesamt (Standard 256)
	AllowPublic bool          // auch oeffentliche Adressen erlauben
	// OnHost wird waehrend des Scans mit Teilergebnissen aufgerufen (I-044): erst wenn
	// offene Ports gefunden wurden, dann mit MAC/Hersteller, dann mit dem Namen. Das
	// Geraet kann dabei mehrfach (mit mehr Angaben) gemeldet werden; Host.Pending ist
	// true, solange der Name noch gesucht wird. Wird aus mehreren Goroutinen
	// aufgerufen und muss daher selbst threadsicher sein. nil = keine Teilergebnisse.
	OnHost func(model.Host)
}

// Progress meldet den Fortschritt: erledigte IPs / Gesamtzahl.
type Progress func(done, total int)

// Run scannt das Ziel und liefert die gefundenen Geraete (nach IP sortiert).
//
// Ablauf: (1) je IP alle Ports per TCP-Connect pruefen - das braucht keine
// Admin-Rechte und laeuft ueberall; (2) danach ARP-Tabelle lesen: Geraete mit
// MAC-Eintrag sind "online", auch wenn alle geprueften Ports zu sind
// (z.B. Smartphones); (3) Namen per Reverse-DNS aufloesen.
func Run(ctx context.Context, opt Options, progress Progress) ([]model.Host, error) {
	ips, err := ExpandTarget(opt.Target, opt.AllowPublic)
	if err != nil {
		return nil, err
	}
	ports := opt.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	conc := opt.Concurrency
	if conc <= 0 {
		conc = 256 // bleibt unter dem typischen Linux-Limit von 1024 offenen Dateien
	}

	sem := make(chan struct{}, conc) // begrenzt gleichzeitige Verbindungen
	var done atomic.Int64
	var mu sync.Mutex
	open := map[netip.Addr][]model.Port{}

	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			found := scanHost(ctx, ip, ports, timeout, sem)
			if len(found) > 0 {
				mu.Lock()
				open[ip] = found
				mu.Unlock()
				// Teilergebnis 1: Geraet mit offenen Ports (noch ohne MAC und Namen).
				emit(opt.OnHost, newHost(ip.String(), "", found))
			}
			if progress != nil {
				progress(int(done.Add(1)), len(ips))
			}
		}(ip)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err // abgebrochen
	}

	// ARP-Tabelle erst NACH den Verbindungsversuchen lesen (sie ist dann gefuellt).
	arp := ReadARP()
	var hosts []model.Host
	for _, ip := range ips {
		mac := arp[ip.String()]
		ps := open[ip]
		if len(ps) == 0 && mac == "" {
			continue // weder offener Port noch ARP-Eintrag -> nicht gefunden
		}
		hosts = append(hosts, newHost(ip.String(), mac, ps))
		emit(opt.OnHost, hosts[len(hosts)-1]) // Teilergebnis 2: jetzt mit MAC und Hersteller
	}
	// Topologie (I-010): Router und Uplink aus dem Standard-Gateway ableiten.
	ApplyGateway(hosts, DefaultGateway())
	// Teilergebnis 3: Namen werden parallel ermittelt; jedes Geraet wird gemeldet, sobald es fertig ist.
	resolveNames(ctx, hosts, func(h model.Host) { emit(opt.OnHost, FinishHost(h)) })
	for i := range hosts {
		hosts[i] = FinishHost(hosts[i])
	}
	return hosts, nil
}

// emit ruft den Teilergebnis-Callback auf (falls gesetzt).
func emit(f func(model.Host), h model.Host) {
	if f != nil {
		f(h)
	}
}

// newHost baut ein noch unvollstaendiges Geraet (Name wird noch gesucht -> Pending).
func newHost(ip, mac string, ports []model.Port) model.Host {
	sort.Slice(ports, func(i, j int) bool { return ports[i].Number < ports[j].Number })
	h := model.Host{IP: ip, MAC: mac, Vendor: Vendor(mac), Ports: orEmpty(ports), Name: pendingName, Pending: true}
	h.OS = GuessOS(h) // Betriebssystem-Vermutung aus Bannern/Ports (I-013)
	h.FillWebLinks()
	return h
}

// FinishHost (auch vom Webserver beim Abbruch genutzt) setzt nach der Namenssuche "bekannt", den Anzeigenamen und Pending=false.
func FinishHost(h model.Host) model.Host {
	// Nur belastbare Quellen (DNS, Zertifikat u.a.) gelten als "bekannt"; ein HTTP-Titel
	// oder Hersteller-Vorschlag ist nur ein Vorschlag und bleibt gelb markiert.
	switch h.NameSource {
	case "dns", "dns-geraet", "mdns", "netbios", "llmnr", "ssdp", "zertifikat":
		h.Known = h.Name != ""
	}
	if h.Name == "" || h.Name == pendingName {
		h.Name = "(unbekannt)"
	}
	h.Pending = false
	h.FillWebLinks()
	return h
}

// pendingName ist der Platzhalter, solange die Namenssuche laeuft.
const pendingName = "(wird ermittelt …)"

// scanHost prueft alle Ports einer IP; jede Verbindung nimmt einen Platz im Semaphor.
func scanHost(ctx context.Context, ip netip.Addr, ports []int, timeout time.Duration, sem chan struct{}) []model.Port {
	var mu sync.Mutex
	var found []model.Port
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(p)))
			if err != nil {
				return // geschlossen, gefiltert oder abgebrochen
			}
			banner := grabBanner(conn, p, 400*time.Millisecond)
			conn.Close()
			if p == 389 { // LDAP: anonyme rootDSE-Abfrage fuer Domaenen-/DC-Infos (I-061)
				if info := QueryRootDSE(ctx, ip.String(), 1500*time.Millisecond); info != "" {
					banner = info
				}
			}
			if p == 631 { // IPP: Drucker-Details (Modell, Firmware, Fuellstaende) ohne Login (I-062)
				if info := QueryIPP(ctx, ip.String(), 1500*time.Millisecond); info != "" {
					banner = info
				}
			}
			var cert *model.Cert
			if httpsPorts[p] { // TLS-Port: Zertifikat lesen (I-004)
				cert = readCert(ctx, ip.String(), p)
			}
			mu.Lock()
			found = append(found, model.Port{Number: p, Service: ServiceName(p), Banner: banner, Cert: cert})
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return found
}

// orEmpty macht aus nil ein leeres Slice (JSON: [] statt null).
func orEmpty(p []model.Port) []model.Port {
	if p == nil {
		return []model.Port{}
	}
	return p
}
