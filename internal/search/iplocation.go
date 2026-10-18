package search

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/geoip"
	"github.com/jrsamsanchez/signalith/internal/query"
)

const (
	errNoGeoIP  = "iplocation needs a GeoIP database, which an admin adds to the geoip folder next to the lookup tables on each server (see iplocation in the query language docs)"
	errBadGeoIP = "iplocation could not read the GeoIP database; the server log says why"
)

// errGeoIPLoading wraps geoip.ErrLoading, so the detection scheduler can
// tell a database that is still loading, and try again, from a bad query.
func errGeoIPLoading() error {
	return &QueryError{Msg: "iplocation's GeoIP database is still loading; try again in a few seconds", Err: geoip.ErrLoading}
}

// maxIPCache caps the addresses one iplocation remembers, so rows that
// repeat an address look it up once.
const maxIPCache = 10_000

// ipLocation adds where each row's address is, from the GeoIP database.
// A row whose field holds no address, or one the database does not list,
// such as a private address, gets no fields. A row with an address it
// lists gets every field, "" where the database has no value, as in
// Splunk.
func (e *Engine) ipLocation(ctx context.Context, res *Result, c *query.IPLocation) error {
	if e.GeoIP == nil {
		return &QueryError{Msg: "iplocation is not available on this server"}
	}
	// The folder's path and why a file failed go to the server log, for
	// admins, not to everyone who searches.
	if file, err := e.GeoIP.Status(); file == "" {
		if errors.Is(err, geoip.ErrNoDatabase) {
			return &QueryError{Msg: errNoGeoIP}
		}
		if errors.Is(err, geoip.ErrLoading) {
			return errGeoIPLoading()
		}
		return &QueryError{Msg: errBadGeoIP}
	}
	lang := c.Lang
	if lang == "" {
		lang = "en"
	}
	names := c.Fields()
	ev := evaluatorFor(ctx)
	type entry struct {
		loc   geoip.Location
		found bool
	}
	cache := map[netip.Addr]entry{}
	added := false
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		v := r[c.Field]
		if mv, ok := v.([]any); ok && len(mv) > 0 {
			v = mv[0]
		}
		s, ok := v.(string)
		if !ok || len(s) > 64 {
			continue
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		ip = ip.WithZone("")
		if !ev.step() {
			return ev.err
		}
		hit, ok := cache[ip]
		if !ok {
			loc, found, err := e.GeoIP.Lookup(ip, lang)
			if errors.Is(err, geoip.ErrLoading) {
				return errGeoIPLoading()
			}
			if err != nil {
				slog.Warn("iplocation could not read the GeoIP database", "err", err)
				return &QueryError{Msg: errBadGeoIP}
			}
			hit = entry{loc, found}
			if len(cache) < maxIPCache {
				cache[ip] = hit
			}
		}
		if !hit.found {
			continue
		}
		l := hit.loc
		vals := []any{l.City, l.Region, l.Country, nil, nil}
		if l.HasCoords {
			vals[3], vals[4] = l.Lat, l.Lon
		}
		if c.AllFields {
			var metro any
			if l.MetroCode != 0 {
				metro = int64(l.MetroCode)
			}
			vals = append(vals, l.Continent, metro, l.Timezone)
		}
		for j, name := range names {
			val := vals[j]
			if val == nil {
				val = ""
			}
			if !ev.newField(r, name) || !ev.charge(valueSize(val)) {
				return ev.err
			}
			r[name] = val
			added = true
		}
	}
	if added {
		for _, name := range names {
			addColumn(res, name)
		}
	}
	return nil
}
