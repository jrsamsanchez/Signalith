// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TAXII 2.1 lets a feed read the indicators of a collection on a TAXII
// server, such as MISP, OpenCTI or a commercial provider.
//
// Each download reads the whole collection (indicator objects only,
// latest versions), a page at a time, and replaces the feed's
// indicators, like any other feed. An incremental pull (added_after)
// would never see indicators that the server revoked or deleted, so they
// would stay until max_age; a full pull removes them at the next run.
//
// A pull has TAXIIRunTimeout in all and taxiiPageTimeout per page. When a
// slow server runs out of time after the first page, the pages read are
// stored and nothing is removed (the rest of the collection was not
// seen); indicators not read this time keep matching until max_age.

// TAXIIMediaType is the Accept header TAXII 2.1 servers expect.
const TAXIIMediaType = "application/taxii+json;version=2.1"

const (
	taxiiPageSize   = 1000
	taxiiMaxPages   = 1000
	taxiiMaxObjects = 500_000
	// TAXIIRunTimeout bounds a scheduled TAXII pull; each page has
	// taxiiPageTimeout.
	TAXIIRunTimeout = 30 * time.Minute
)

// taxiiPageTimeout bounds one page of a TAXII pull; tests lower it.
var taxiiPageTimeout = 2 * time.Minute

type taxiiEnvelope struct {
	More    bool         `json:"more"`
	Next    string       `json:"next"`
	Objects []stixObject `json:"objects"`
}

// apiRoot returns a TAXII API root URL ending in a slash.
func apiRoot(u string) string {
	u = strings.TrimSpace(u)
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	return u
}

func (f *Feeds) fetchTAXII(ctx context.Context, fd Feed, now time.Time, lim fetchLimits) (*fetched, error) {
	base := apiRoot(fd.URL) + "collections/" + url.PathEscape(fd.Collection) + "/objects/"
	q := url.Values{"match[type]": {"indicator"}, "limit": {strconv.Itoa(taxiiPageSize)}}
	pages := lim.Pages
	if pages <= 0 {
		pages = taxiiMaxPages
	}
	maxBytes := lim.MaxBytes
	if maxBytes <= 0 {
		maxBytes = MaxDownload
	}
	out := &fetched{}
	var objs []stixObject
	for page := 0; ; page++ {
		if page == pages || len(objs) >= taxiiMaxObjects {
			out.Truncated = true
			break
		}
		left := maxBytes - out.Bytes
		if left <= 0 {
			out.Truncated = true // the size limit is reached
			break
		}
		pctx, cancel := context.WithTimeout(ctx, taxiiPageTimeout)
		data, _, hdr, err := f.httpGet(pctx, fd, base+"?"+q.Encode(), TAXIIMediaType, fetchLimits{MaxBytes: left})
		cancel()
		var tb *TooBigError
		if errors.As(err, &tb) && page > 0 {
			out.Truncated = true
			break
		}
		if err != nil && page > 0 && slow(err) && !errors.Is(ctx.Err(), context.Canceled) {
			// Keep what the slow server sent so far.
			out.Truncated, out.Incomplete = true, true
			out.Note = fmt.Sprintf("The server was slow, so only %s of the collection (%d objects) were read in the time allowed. Indicators not read this time are kept until they expire.",
				plural(page, "page"), len(objs))
			break
		}
		if err != nil {
			return nil, err
		}
		out.Bytes += int64(len(data))
		var env taxiiEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, plain("The server's answer is not a TAXII 2.1 envelope. Check that the URL is the API root, such as https://cti.example.com/api1/.")
		}
		objs = append(objs, env.Objects...)
		if !env.More || len(env.Objects) == 0 {
			break
		}
		// TAXII 2.1 pages with "next"; some servers page by the date of
		// the last object instead.
		if env.Next != "" {
			q.Set("next", env.Next)
		} else if last := hdr.Get("X-TAXII-Date-Added-Last"); last != "" && last != q.Get("added_after") {
			q.Set("added_after", last)
		} else {
			out.Truncated = true
			break
		}
	}
	out.Result = stixIndicators(objs, ParseOptions{Format: FormatSTIX, Type: fd.Type, Now: now, Keep: lim.Keep})
	out.Result.Format = FormatSTIX
	if out.Truncated && out.Note == "" {
		out.Note = fmt.Sprintf("The collection has more objects; only the first %d were read.", len(objs))
	}
	return out, nil
}

// slow reports whether a download ran out of time.
func slow(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// TAXIICollection is a collection a TAXII server offers.
type TAXIICollection struct {
	APIRoot     string   `json:"api_root"`
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	CanRead     bool     `json:"can_read"`
	MediaTypes  []string `json:"media_types,omitempty"`
}

// TAXIIServer is what Collections found.
type TAXIIServer struct {
	Title       string            `json:"title,omitempty"`
	Collections []TAXIICollection `json:"collections"`
}

// Collections lists the collections of the TAXII server at fd.URL, which
// may be an API root, the discovery URL (…/taxii2/) or the server's
// address, using fd's credentials.
func (f *Feeds) Collections(ctx context.Context, fd Feed) (*TAXIIServer, error) {
	fd.Kind = KindTAXII
	u, err := url.Parse(strings.TrimSpace(fd.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, plain("Enter the http(s) address of the TAXII server's API root, such as https://cti.example.com/api1/.")
	}
	if u.User != nil {
		return nil, plain("Put the user name and password in their own fields, not in the URL.")
	}
	lim := fetchLimits{MaxBytes: 4 << 20}
	srv := &TAXIIServer{Collections: []TAXIICollection{}}
	// Most people paste the API root.
	cols, err := f.taxiiCollections(ctx, fd, apiRoot(fd.URL), lim)
	if err == nil {
		srv.Collections = cols
		return srv, nil
	}
	if !notTAXII(err) {
		return nil, err // a sign-in, network or server problem
	}
	// Otherwise ask the discovery service which API roots there are.
	disc := apiRoot(fd.URL)
	if !strings.Contains(u.Path, "taxii2") {
		disc = u.Scheme + "://" + u.Host + "/taxii2/"
	}
	errNoServer := plain("No TAXII 2.1 server answered at this address. Enter the API root URL, such as https://cti.example.com/api1/, or the discovery URL ending in /taxii2/.")
	data, _, _, err := f.httpGet(ctx, fd, disc, TAXIIMediaType, lim)
	if err != nil {
		if notTAXII(err) {
			return nil, errNoServer
		}
		return nil, err
	}
	var d struct {
		Title    string   `json:"title"`
		Default  string   `json:"default"`
		APIRoots []string `json:"api_roots"`
	}
	if !looksLikeJSON(data) || json.Unmarshal(data, &d) != nil || len(d.APIRoots) == 0 {
		return nil, errNoServer
	}
	srv.Title = d.Title
	base, _ := url.Parse(disc)
	roots := d.APIRoots
	if len(roots) > 10 {
		roots = roots[:10]
	}
	var firstErr error
	for _, r := range roots {
		ru, err := base.Parse(r)
		if err != nil {
			continue
		}
		cols, err := f.taxiiCollections(ctx, fd, apiRoot(ru.String()), lim)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if r == d.Default {
			srv.Collections = append(cols, srv.Collections...)
		} else {
			srv.Collections = append(srv.Collections, cols...)
		}
	}
	if len(srv.Collections) == 0 && firstErr != nil {
		if notTAXII(firstErr) {
			return nil, errNoServer
		}
		return nil, firstErr
	}
	return srv, nil
}

var errNotCollections = errors.New("not a TAXII collections list")

// notTAXII reports whether an error means the address is not a TAXII API
// root (as opposed to a sign-in, network or server problem).
func notTAXII(err error) bool {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Code == 404 || he.Code == 405 || he.Code == 406 || he.Code == 400
	}
	return errors.Is(err, errNotCollections)
}

func (f *Feeds) taxiiCollections(ctx context.Context, fd Feed, root string, lim fetchLimits) ([]TAXIICollection, error) {
	data, _, _, err := f.httpGet(ctx, fd, root+"collections/", TAXIIMediaType, lim)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Collections []TAXIICollection `json:"collections"`
	}
	if !looksLikeJSON(data) || json.Unmarshal(data, &resp) != nil {
		return nil, errNotCollections
	}
	out := make([]TAXIICollection, 0, len(resp.Collections))
	for _, c := range resp.Collections {
		if c.ID == "" {
			continue
		}
		c.APIRoot = root
		if c.Title == "" {
			c.Title = c.ID
		}
		out = append(out, c)
	}
	return out, nil
}
