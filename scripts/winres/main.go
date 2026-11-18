//go:build ignore

// Erzeugt aus einer .ico-Datei eine Windows-Ressourcendatei (COFF-Objekt, ".syso"),
// damit netzscanner.exe selbst ein Icon hat (I-086). Go bindet Dateien der Form
// "rsrc_windows_<arch>.syso" beim Windows-Build automatisch ein.
//
// Nur Go-Standardbibliothek, keine Fremdwerkzeuge. Aufruf (siehe scripts/make-winres.sh):
//
//	go run scripts/winres/main.go -ico installer/netzscanner.ico -out cmd/netzscanner
//
// Aufbau der Ressource (wie bei jedem Windows-Programm):
//
//	RT_ICON (Typ 3)       Nr. 1..n   je ein Bild der .ico (PNG oder BMP, unveraendert)
//	RT_GROUP_ICON (Typ 14) Nr. 1     Verzeichnis, das die Bilder zu EINEM Icon bündelt
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Ein Knoten des Ressourcenbaums: entweder Verzeichnis (kids) oder Blatt (data).
type node struct {
	kids map[uint32]*node
	data []byte
	// Berechnete Lage im Abschnitt:
	off     uint32 // Verzeichnis: Anfang des Verzeichnisses; Blatt: Anfang des Datensatz-Eintrags
	dataOff uint32 // Blatt: Anfang der Rohdaten
}

func dir() *node { return &node{kids: map[uint32]*node{}} }

func (n *node) isDir() bool { return n.kids != nil }

// ids liefert die Schluessel sortiert (Windows verlangt aufsteigende Reihenfolge).
func (n *node) ids() []uint32 {
	k := make([]uint32, 0, len(n.kids))
	for id := range n.kids {
		k = append(k, id)
	}
	sort.Slice(k, func(i, j int) bool { return k[i] < k[j] })
	return k
}

// layout vergibt Offsets: erst alle Verzeichnisse, dann alle Datensatz-Eintraege, dann die Rohdaten.
func layout(root *node) (total uint32, leaves []*node) {
	var dirs []*node
	var walk func(*node)
	walk = func(n *node) {
		if n.isDir() {
			dirs = append(dirs, n)
			for _, id := range n.ids() {
				walk(n.kids[id])
			}
		} else {
			leaves = append(leaves, n)
		}
	}
	walk(root)
	var pos uint32
	for _, d := range dirs {
		d.off = pos
		pos += 16 + 8*uint32(len(d.kids))
	}
	for _, l := range leaves {
		l.off = pos
		pos += 16
	}
	for _, l := range leaves {
		pos = (pos + 3) &^ 3 // Rohdaten 4-Byte-ausgerichtet
		l.dataOff = pos
		pos += uint32(len(l.data))
	}
	return (pos + 3) &^ 3, leaves
}

// serialize schreibt den Ressourcenbaum in Bytes und liefert die Stellen, an denen ein
// Relokationseintrag (RVA) noetig ist (Feld "OffsetToData" jedes Datensatz-Eintrags).
func serialize(root *node) (blob []byte, relocAt []uint32) {
	total, leaves := layout(root)
	blob = make([]byte, total)
	le := binary.LittleEndian
	var walk func(*node)
	walk = func(n *node) {
		if !n.isDir() {
			return
		}
		le.PutUint16(blob[n.off+14:], uint16(len(n.kids))) // NumberOfIdEntries (keine benannten Eintraege)
		for i, id := range n.ids() {
			e := n.off + 16 + 8*uint32(i)
			kid := n.kids[id]
			le.PutUint32(blob[e:], id)
			if kid.isDir() {
				le.PutUint32(blob[e+4:], 0x80000000|kid.off)
			} else {
				le.PutUint32(blob[e+4:], kid.off)
			}
			walk(kid)
		}
	}
	walk(root)
	for _, l := range leaves {
		le.PutUint32(blob[l.off:], l.dataOff) // wird per Relokation zur RVA
		le.PutUint32(blob[l.off+4:], uint32(len(l.data)))
		le.PutUint32(blob[l.off+8:], 0) // Codepage
		copy(blob[l.dataOff:], l.data)
		relocAt = append(relocAt, l.off)
	}
	return blob, relocAt
}

// icoImage ist ein Bild aus der .ico samt Kopfdaten.
type icoImage struct {
	w, h, colors, reserved byte
	planes, bits           uint16
	data                   []byte
}

// readICO zerlegt eine .ico-Datei in ihre Bilder.
func readICO(b []byte) ([]icoImage, error) {
	le := binary.LittleEndian
	if len(b) < 6 || le.Uint16(b[0:]) != 0 || le.Uint16(b[2:]) != 1 {
		return nil, fmt.Errorf("keine gueltige .ico-Datei")
	}
	n := int(le.Uint16(b[4:]))
	var imgs []icoImage
	for i := 0; i < n; i++ {
		e := 6 + 16*i
		if e+16 > len(b) {
			return nil, fmt.Errorf("ico: Verzeichnis abgeschnitten")
		}
		size, off := le.Uint32(b[e+8:]), le.Uint32(b[e+12:])
		if uint64(off)+uint64(size) > uint64(len(b)) {
			return nil, fmt.Errorf("ico: Bild %d ausserhalb der Datei", i)
		}
		imgs = append(imgs, icoImage{b[e], b[e+1], b[e+2], b[e+3], le.Uint16(b[e+4:]), le.Uint16(b[e+6:]), b[off : off+size]})
	}
	if len(imgs) == 0 {
		return nil, fmt.Errorf("ico: keine Bilder")
	}
	return imgs, nil
}

// buildTree baut RT_ICON-Bilder und das RT_GROUP_ICON-Verzeichnis (Sprache 0x0409).
func buildTree(imgs []icoImage) *node {
	const rtIcon, rtGroupIcon, lang = 3, 14, 0x0409
	le := binary.LittleEndian
	root, icons, group := dir(), dir(), dir()
	root.kids[rtIcon], root.kids[rtGroupIcon] = icons, group

	var g bytes.Buffer
	binary.Write(&g, le, [3]uint16{0, 1, uint16(len(imgs))}) // GRPICONDIR
	for i, im := range imgs {
		id := uint32(i + 1)
		l := dir()
		l.kids[lang] = &node{data: im.data}
		icons.kids[id] = l
		g.Write([]byte{im.w, im.h, im.colors, im.reserved}) // GRPICONDIRENTRY
		binary.Write(&g, le, im.planes)
		binary.Write(&g, le, im.bits)
		binary.Write(&g, le, uint32(len(im.data)))
		binary.Write(&g, le, uint16(id))
	}
	gl := dir()
	gl.kids[lang] = &node{data: g.Bytes()}
	group.kids[1] = gl
	return root
}

// coff verpackt die Ressourcen in ein COFF-Objekt mit Abschnitt ".rsrc".
func coff(machine, relocType uint16, blob []byte, relocAt []uint32) []byte {
	le := binary.LittleEndian
	const hdr, sect = 20, 40
	rawOff := uint32(hdr + sect)
	relOff := rawOff + uint32(len(blob))
	symOff := relOff + uint32(10*len(relocAt))

	var b bytes.Buffer
	// Dateikopf: 1 Abschnitt, 1 Symbol + 1 Zusatzeintrag = 2 Symboltabellen-Eintraege
	binary.Write(&b, le, machine)
	binary.Write(&b, le, uint16(1))
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, symOff)
	binary.Write(&b, le, uint32(2))
	binary.Write(&b, le, uint16(0))
	binary.Write(&b, le, uint16(0))
	// Abschnittskopf ".rsrc": initialisierte Daten, lesbar
	b.Write([]byte(".rsrc\x00\x00\x00"))
	binary.Write(&b, le, uint32(0)) // VirtualSize
	binary.Write(&b, le, uint32(0)) // VirtualAddress
	binary.Write(&b, le, uint32(len(blob)))
	binary.Write(&b, le, rawOff)
	binary.Write(&b, le, relOff)
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, uint16(len(relocAt)))
	binary.Write(&b, le, uint16(0))
	binary.Write(&b, le, uint32(0x40000040))
	b.Write(blob)
	// Relokationen: Feld "OffsetToData" soll eine RVA (relativ zum Abbildanfang) werden
	for _, at := range relocAt {
		binary.Write(&b, le, at)
		binary.Write(&b, le, uint32(0)) // Symbol 0 = ".rsrc"
		binary.Write(&b, le, relocType)
	}
	// Symboltabelle: Abschnittssymbol ".rsrc" + Zusatzeintrag
	b.Write([]byte(".rsrc\x00\x00\x00"))
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, int16(1)) // Abschnitt Nr. 1
	binary.Write(&b, le, uint16(0))
	b.WriteByte(3) // STATIC
	b.WriteByte(1) // 1 Zusatzeintrag
	binary.Write(&b, le, uint32(len(blob)))
	binary.Write(&b, le, uint16(len(relocAt)))
	binary.Write(&b, le, uint16(0))
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, uint16(0))
	b.Write([]byte{0, 0, 0, 0}) // Auswahlart (1 Byte) + Auffuellung (3 Bytes) = 18 Bytes Zusatzeintrag
	binary.Write(&b, le, uint32(4))   // leere Zeichenkettentabelle
	return b.Bytes()
}

func main() {
	icoPath := flag.String("ico", "installer/netzscanner.ico", ".ico-Datei")
	outDir := flag.String("out", "cmd/netzscanner", "Zielordner fuer die .syso-Dateien")
	flag.Parse()

	raw, err := os.ReadFile(*icoPath)
	if err == nil {
		var imgs []icoImage
		if imgs, err = readICO(raw); err == nil {
			blob, relocAt := serialize(buildTree(imgs))
			// Go-Architektur -> (COFF-Maschine, Relokationsart "ADDR32NB")
			targets := map[string][2]uint16{"amd64": {0x8664, 3}, "arm64": {0xAA64, 2}}
			for arch, t := range targets {
				p := filepath.Join(*outDir, "rsrc_windows_"+arch+".syso")
				if err = os.WriteFile(p, coff(t[0], t[1], blob, relocAt), 0o644); err != nil {
					break
				}
				fmt.Println("geschrieben:", p, len(imgs), "Bilder")
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
}
