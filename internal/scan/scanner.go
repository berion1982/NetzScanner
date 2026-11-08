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
		sort.Slice(ps, func(i, j int) bool { return ps[i].Number < ps[j].Number })
		hosts = append(hosts, model.Host{IP: ip.String(), MAC: mac, Vendor: Vendor(mac), Ports: orEmpty(ps)})
	}
	resolveNames(ctx, hosts)
	for i := range hosts {
		hosts[i].Known = hosts[i].Name != "" && hosts[i].Name != "(unbekannt)"
		if hosts[i].Name == "" {
			hosts[i].Name = "(unbekannt)"
		}
		hosts[i].FillWebLinks()
	}
	return hosts, nil
}

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
			mu.Lock()
			found = append(found, model.Port{Number: p, Service: ServiceName(p), Banner: banner})
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return found
}

// resolveNames fragt per Reverse-DNS den Namen je Host ab (parallel, 1,5s Timeout).
func resolveNames(ctx context.Context, hosts []model.Host) {
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(h *model.Host) {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(c, h.IP)
			if err == nil && len(names) > 0 {
				h.Name = sanitize(trimDot(names[0]))
			}
		}(&hosts[i])
	}
	wg.Wait()
}

func trimDot(s string) string {
	if n := len(s); n > 0 && s[n-1] == '.' {
		return s[:n-1]
	}
	return s
}

// orEmpty macht aus nil ein leeres Slice (JSON: [] statt null).
func orEmpty(p []model.Port) []model.Port {
	if p == nil {
		return []model.Port{}
	}
	return p
}
