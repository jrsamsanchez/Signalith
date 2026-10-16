package baselines

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// The sign-in country and network checks need to know which network an
// address belongs to. Signalith reads the free IP-to-ASN database of
// iptoasn.com, which is in the public domain (PDDL): one line per address
// range with its autonomous system (AS) number, the country the AS is
// registered in, and the AS's name:
//
//	1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
//
// The country is where the network is registered, which is usually, but
// not always, where its users are: a VPN, a cloud provider or a roaming
// mobile network can be registered elsewhere.

// DefaultIPDatabase is where the database is downloaded from.
const DefaultIPDatabase = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

// Limits of the database.
const (
	maxIPDBBytes   = 64 << 20  // as downloaded, compressed or not
	maxIPDBRawSize = 512 << 20 // uncompressed
	maxIPDBRows    = 4_000_000
	// maxIPDBStored is the most the stored copy may take, gzipped, so the
	// one document that holds it stays well within what OpenSearch takes.
	maxIPDBStored = 24 << 20
)

// Network is what the database says of one address.
type Network struct {
	ASN     uint32
	Country string // ISO 3166 two-letter code, upper case; "" when not known
	Name    string // the AS's name, such as CLOUDFLARENET
}

// AS returns the AS number as AS13335.
func (n Network) AS() string { return "AS" + strconv.FormatUint(uint64(n.ASN), 10) }

type v4Range struct {
	start, end uint32
	asn        uint32
	cc         [2]byte
}

type v6Range struct {
	start, end [16]byte
	asn        uint32
	cc         [2]byte
}

// IPDB looks up the network of an address.
type IPDB struct {
	v4    []v4Range
	v6    []v6Range
	names map[uint32]string
}

// Rows is how many address ranges the database has.
func (d *IPDB) Rows() int {
	if d == nil {
		return 0
	}
	return len(d.v4) + len(d.v6)
}

// ParseIPDB reads the database, gzipped or not. Ranges with no AS (not
// routed) are left out.
func ParseIPDB(r io.Reader) (*IPDB, error) {
	br := bufio.NewReader(&capped{r: r, left: maxIPDBBytes, what: "the IP database file"})
	if head, _ := br.Peek(2); len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		br = bufio.NewReader(zr)
	}
	d := &IPDB{names: map[uint32]string{}}
	var read int64
	line := 0
	for {
		s, err := br.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		read += int64(len(s))
		if read > maxIPDBRawSize {
			return nil, fmt.Errorf("the IP database is larger than %d MB", maxIPDBRawSize>>20)
		}
		if s != "" {
			line++
			if perr := d.addLine(strings.TrimRight(s, "\r\n")); perr != nil {
				return nil, fmt.Errorf("line %d: %w", line, perr)
			}
			if d.Rows() > maxIPDBRows {
				return nil, fmt.Errorf("the IP database has more than %d ranges", maxIPDBRows)
			}
		}
		if err != nil {
			break
		}
	}
	if d.Rows() == 0 {
		return nil, errors.New("the IP database has no address ranges: expected lines of start, end, AS number, country and name, separated by tabs")
	}
	sort.Slice(d.v4, func(i, j int) bool { return d.v4[i].start < d.v4[j].start })
	sort.Slice(d.v6, func(i, j int) bool { return bytes.Compare(d.v6[i].start[:], d.v6[j].start[:]) < 0 })
	return d, nil
}

// capped reads at most left bytes, and fails past them rather than end
// early, so a database that is too large is refused, not cut.
type capped struct {
	r    io.Reader
	left int64
	what string
}

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, _ := c.r.Read(one[:]); n > 0 {
			return 0, fmt.Errorf("%s is larger than %d MB", c.what, maxIPDBBytes>>20)
		}
		return c.r.Read(p[:0])
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// ctxReader stops a read, and so parsing the database, once ctx ends,
// so a server stopping doesn't wait for a large file to be read.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func (d *IPDB) addLine(s string) error {
	if s == "" || s[0] == '#' {
		return nil
	}
	f := strings.SplitN(s, "\t", 5)
	if len(f) < 4 {
		return errors.New("expected start, end, AS number and country separated by tabs")
	}
	start, err1 := netip.ParseAddr(f[0])
	end, err2 := netip.ParseAddr(f[1])
	if err1 != nil || err2 != nil || start.Is4() != end.Is4() || end.Less(start) {
		return errors.New("not an address range")
	}
	asn, err := strconv.ParseUint(f[2], 10, 32)
	if err != nil {
		return errors.New("the AS number is not a number")
	}
	if asn == 0 {
		return nil // not routed
	}
	var cc [2]byte
	if c := strings.ToUpper(strings.TrimSpace(f[3])); len(c) == 2 && c != "ZZ" && isAlpha(c) {
		cc = [2]byte{c[0], c[1]}
	}
	if len(f) == 5 {
		if name := strings.TrimSpace(f[4]); name != "" && d.names[uint32(asn)] == "" {
			d.names[uint32(asn)] = short(name)
		}
	}
	if start.Is4() {
		d.v4 = append(d.v4, v4Range{start: v4(start), end: v4(end), asn: uint32(asn), cc: cc})
	} else {
		d.v6 = append(d.v6, v6Range{start: start.As16(), end: end.As16(), asn: uint32(asn), cc: cc})
	}
	return nil
}

func isAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

func v4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Public reports whether an address can belong to a network on the
// internet: not private, loopback, link-local, shared (CGNAT),
// documentation, multicast or unspecified.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space (CGNAT)
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), // documentation
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// Lookup returns the network of a public address.
func (d *IPDB) Lookup(a netip.Addr) (Network, bool) {
	if d == nil {
		return Network{}, false
	}
	a = a.Unmap()
	if a.Is4() {
		k := v4(a)
		i := sort.Search(len(d.v4), func(i int) bool { return d.v4[i].start > k }) - 1
		if i < 0 || d.v4[i].end < k {
			return Network{}, false
		}
		return d.network(d.v4[i].asn, d.v4[i].cc), true
	}
	k := a.As16()
	i := sort.Search(len(d.v6), func(i int) bool { return bytes.Compare(d.v6[i].start[:], k[:]) > 0 }) - 1
	if i < 0 || bytes.Compare(d.v6[i].end[:], k[:]) < 0 {
		return Network{}, false
	}
	return d.network(d.v6[i].asn, d.v6[i].cc), true
}

func (d *IPDB) network(asn uint32, cc [2]byte) Network {
	n := Network{ASN: asn, Name: d.names[asn]}
	if cc[0] != 0 {
		n.Country = string(cc[:])
	}
	return n
}

// encode writes the database back as gzipped lines in the format it was
// read from, so a stored copy is read with ParseIPDB.
func (d *IPDB) encode(ctx context.Context) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriter(zw)
	cc := func(c [2]byte) string {
		if c[0] == 0 {
			return "None"
		}
		return string(c[:])
	}
	for i, r := range d.v4 {
		if i%65536 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s := netip.AddrFrom4([4]byte{byte(r.start >> 24), byte(r.start >> 16), byte(r.start >> 8), byte(r.start)})
		e := netip.AddrFrom4([4]byte{byte(r.end >> 24), byte(r.end >> 16), byte(r.end >> 8), byte(r.end)})
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", s, e, r.asn, cc(r.cc), d.names[r.asn])
	}
	for i, r := range d.v6 {
		if i%65536 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", netip.AddrFrom16(r.start), netip.AddrFrom16(r.end), r.asn, cc(r.cc), d.names[r.asn])
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// countryNames are the English names of the countries sign-ins come
// from most, for messages; others show their code.
var countryNames = map[string]string{
	"AE": "the United Arab Emirates", "AR": "Argentina", "AT": "Austria", "AU": "Australia", "BD": "Bangladesh", "BE": "Belgium",
	"BG": "Bulgaria", "BR": "Brazil", "BY": "Belarus", "CA": "Canada", "CH": "Switzerland", "CL": "Chile", "CN": "China",
	"CO": "Colombia", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark", "DZ": "Algeria", "EG": "Egypt", "ES": "Spain",
	"FI": "Finland", "FR": "France", "GB": "the United Kingdom", "GR": "Greece", "HK": "Hong Kong", "HU": "Hungary",
	"ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IN": "India", "IQ": "Iraq", "IR": "Iran", "IT": "Italy", "JP": "Japan",
	"KE": "Kenya", "KP": "North Korea", "KR": "South Korea", "KZ": "Kazakhstan", "LT": "Lithuania", "LU": "Luxembourg",
	"LV": "Latvia", "MA": "Morocco", "MX": "Mexico", "MY": "Malaysia", "NG": "Nigeria", "NL": "the Netherlands", "NO": "Norway",
	"NZ": "New Zealand", "PE": "Peru", "PH": "the Philippines", "PK": "Pakistan", "PL": "Poland", "PT": "Portugal",
	"RO": "Romania", "RS": "Serbia", "RU": "Russia", "SA": "Saudi Arabia", "SE": "Sweden", "SG": "Singapore", "SK": "Slovakia",
	"TH": "Thailand", "TR": "Türkiye", "TW": "Taiwan", "UA": "Ukraine", "US": "the United States", "VE": "Venezuela",
	"VN": "Vietnam", "ZA": "South Africa",
}

// CountryName names a country code for a sentence.
func CountryName(cc string) string {
	if n, ok := countryNames[cc]; ok {
		return n + " (" + cc + ")"
	}
	return cc
}
