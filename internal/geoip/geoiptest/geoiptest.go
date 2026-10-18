// Package geoiptest writes small GeoIP databases in the MaxMind DB format
// for tests, so they need no downloaded file.
package geoiptest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"sort"
)

// City is one network's record, in the layout of a GeoLite2 City database.
type City struct {
	City, Region, Country, CountryCode, Continent, Timezone string
	Lat, Lon                                                float64
	MetroCode                                               uint16
	// Names in other languages, by language then English name.
	Other map[string]map[string]string
}

// Build returns a database (ip_version 6, as the real ones) of the given
// type, such as GeoLite2-City, listing each network. IPv4 networks are
// stored under ::/96 like in the real databases.
func Build(dbType string, networks map[string]City) ([]byte, error) {
	t := &trie{}
	t.nodes = append(t.nodes, node{left: child{data: -1}, right: child{data: -1}})
	var data bytes.Buffer
	keys := make([]string, 0, len(networks))
	for k := range networks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p, err := netip.ParsePrefix(k)
		if err != nil {
			return nil, err
		}
		bits := p.Bits()
		a := p.Addr()
		if a.Is4() {
			var b [16]byte
			v4 := a.As4()
			copy(b[12:], v4[:])
			a = netip.AddrFrom16(b)
			bits += 96
		}
		off := data.Len()
		encode(&data, networks[k].record())
		t.insert(a.As16(), bits, off)
	}
	nodeCount := len(t.nodes)
	if nodeCount >= 1<<24-16-data.Len() {
		return nil, fmt.Errorf("too big for 24-bit records")
	}
	var out bytes.Buffer
	for _, n := range t.nodes {
		for _, c := range []child{n.left, n.right} {
			v := nodeCount // no data
			switch {
			case c.node > 0:
				v = c.node
			case c.data >= 0:
				v = nodeCount + 16 + c.data
			}
			out.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	encode(&out, ordered{
		{"binary_format_major_version", uint16(2)},
		{"binary_format_minor_version", uint16(0)},
		{"build_epoch", uint64(1791676800)},
		{"database_type", dbType},
		{"description", ordered{{"en", "Signalith test database"}}},
		{"ip_version", uint16(6)},
		{"languages", []any{"en", "de"}},
		{"node_count", uint32(nodeCount)},
		{"record_size", uint16(24)},
	})
	return out.Bytes(), nil
}

func (c City) record() ordered {
	names := func(en string) ordered {
		n := ordered{{"en", en}}
		for lang, m := range c.Other {
			if v, ok := m[en]; ok {
				n = append(n, kv{lang, v})
			}
		}
		return n
	}
	var r ordered
	if c.City != "" {
		r = append(r, kv{"city", ordered{{"names", names(c.City)}}})
	}
	if c.Continent != "" {
		r = append(r, kv{"continent", ordered{{"code", "XX"}, {"names", names(c.Continent)}}})
	}
	if c.Country != "" {
		r = append(r, kv{"country", ordered{{"iso_code", c.CountryCode}, {"names", names(c.Country)}}})
	}
	if c.Lat != 0 || c.Lon != 0 || c.Timezone != "" {
		loc := ordered{{"latitude", c.Lat}, {"longitude", c.Lon}}
		if c.MetroCode != 0 {
			loc = append(loc, kv{"metro_code", c.MetroCode})
		}
		if c.Timezone != "" {
			loc = append(loc, kv{"time_zone", c.Timezone})
		}
		r = append(r, kv{"location", loc})
	}
	if c.Region != "" {
		r = append(r, kv{"subdivisions", []any{ordered{{"iso_code", "R"}, {"names", names(c.Region)}}}})
	}
	return r
}

type kv struct {
	k string
	v any
}

type ordered []kv

type child struct {
	node int // > 0: the next node
	data int // >= 0 when node is 0: offset in the data section
}

type node struct{ left, right child }

type trie struct{ nodes []node }

func (t *trie) insert(addr [16]byte, bits, data int) {
	n := 0
	for i := 0; i < bits; i++ {
		bit := addr[i/8] >> (7 - i%8) & 1
		c := &t.nodes[n].left
		if bit == 1 {
			c = &t.nodes[n].right
		}
		if i == bits-1 {
			*c = child{data: data}
			return
		}
		if c.node == 0 {
			t.nodes = append(t.nodes, node{left: child{data: -1}, right: child{data: -1}})
			// The append may have moved the slice.
			c = &t.nodes[n].left
			if bit == 1 {
				c = &t.nodes[n].right
			}
			c.node = len(t.nodes) - 1
		}
		n = c.node
	}
}

func encode(b *bytes.Buffer, v any) {
	switch v := v.(type) {
	case string:
		head(b, 2, len(v))
		b.WriteString(v)
	case float64:
		head(b, 3, 8)
		binary.Write(b, binary.BigEndian, math.Float64bits(v)) //nolint:errcheck
	case uint16:
		head(b, 5, 2)
		binary.Write(b, binary.BigEndian, v) //nolint:errcheck
	case uint32:
		head(b, 6, 4)
		binary.Write(b, binary.BigEndian, v) //nolint:errcheck
	case uint64:
		head(b, 9, 8)
		binary.Write(b, binary.BigEndian, v) //nolint:errcheck
	case ordered:
		head(b, 7, len(v))
		for _, e := range v {
			encode(b, e.k)
			encode(b, e.v)
		}
	case []any:
		head(b, 11, len(v))
		for _, e := range v {
			encode(b, e)
		}
	default:
		panic(fmt.Sprintf("geoiptest: cannot encode %T", v))
	}
}

func head(b *bytes.Buffer, typ, size int) {
	var ext []byte
	switch {
	case size < 29:
	case size < 285:
		ext = []byte{byte(size - 29)}
		size = 29
	case size < 65821:
		s := size - 285
		ext = []byte{byte(s >> 8), byte(s)}
		size = 30
	default:
		s := size - 65821
		ext = []byte{byte(s >> 16), byte(s >> 8), byte(s)}
		size = 31
	}
	if typ > 7 {
		b.WriteByte(byte(size))
		b.WriteByte(byte(typ - 7))
	} else {
		b.WriteByte(byte(typ<<5 | size))
	}
	b.Write(ext)
}
