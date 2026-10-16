package shared

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Every document in the config index is an Envelope: who changed it and
// when, its revision, its payload as a JSON string, and a MAC.
//
// The MAC covers the values of the fields, not the bytes OpenSearch
// stores: OpenSearch writes a source out again in its own way whenever
// something rewrites the document, and the payload is an opaque string so
// nothing in it can change. UpdatedAt is kept as the text it was written
// as for the same reason.

// role is the index role in the MAC. It is not the index's name, so a
// config index made again under the same prefix still verifies.
const role = "config"

// macVersion starts every MAC this version makes.
const macVersion = "m1"

// By says who changed a document: a user (or "signalith" for the server
// itself) on a server, by its name.
type By struct {
	User string `json:"user"`
	Node string `json:"node"`
}

// Envelope is a document of the config index as stored.
type Envelope struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Format    int    `json:"format"`
	Rev       int64  `json:"rev"`
	Deleted   bool   `json:"deleted"`
	UpdatedAt string `json:"updated_at"`
	UpdatedBy By     `json:"updated_by"`
	// Body is the payload's JSON text.
	Body string `json:"body"`
	MAC  string `json:"mac"`
	// WriteID is the store's mark of the write that made this copy; the
	// MAC leaves it out.
	WriteID string `json:"write_id,omitempty"`
	// Extra holds fields of the envelope this version does not know, such
	// as one a newer version adds. They are not signed, and are written
	// back as they are.
	Extra Extra `json:"-"`
}

// envelopeFields are the fields Envelope knows.
var envelopeFields = []string{"kind", "id", "format", "rev", "deleted", "updated_at", "updated_by", "body", "mac", "write_id"}

type envelopeJSON Envelope

// MarshalJSON writes the envelope with its Extra fields.
func (e Envelope) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(envelopeJSON(e))
	if err != nil {
		return nil, err
	}
	return MergeExtra(raw, e.Extra)
}

// UnmarshalJSON reads an envelope, keeping fields it does not know in
// Extra.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	var v envelopeJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for _, k := range envelopeFields {
		delete(all, k)
	}
	v.Extra = nil
	if len(all) > 0 {
		v.Extra = all
	}
	*e = Envelope(v)
	return nil
}

// canonical is the text the MAC covers: fixed field values, each ended by
// a zero byte, the body last.
func canonical(id string, e *Envelope) ([]byte, error) {
	fields := []string{"sgl-config-v1", role, id, e.Kind, strconv.Itoa(e.Format), strconv.FormatInt(e.Rev, 10),
		strconv.FormatBool(e.Deleted), e.UpdatedAt, e.UpdatedBy.User, e.UpdatedBy.Node}
	var b bytes.Buffer
	for _, f := range fields {
		// A zero byte inside a field could make two documents' texts the
		// same; only the body, which comes last, may hold one.
		if strings.IndexByte(f, 0) >= 0 {
			return nil, errors.New("a field holds a zero byte")
		}
		b.WriteString(f)
		b.WriteByte(0)
	}
	b.WriteString(e.Body)
	return b.Bytes(), nil
}

func mac(k *ClusterKey, text []byte) []byte {
	h := hmac.New(sha256.New, k.macKey)
	h.Write(text)
	return h.Sum(nil)
}

// Sign sets the MAC of the document id with k.
func Sign(k *ClusterKey, id string, e *Envelope) error {
	text, err := canonical(id, e)
	if err != nil {
		return fmt.Errorf("cannot sign %s: %w", id, err)
	}
	e.MAC = macVersion + ":" + k.ID() + ":" + base64.RawURLEncoding.EncodeToString(mac(k, text))
	return nil
}

var (
	// ErrNoMAC is a document without a MAC.
	ErrNoMAC = errors.New("it has no MAC")
	// ErrBadMAC is a document whose MAC does not match its content: it was
	// changed outside Signalith, or forged.
	ErrBadMAC = errors.New("its MAC does not match")
	// ErrNewerMAC is a MAC of a kind a newer version makes.
	ErrNewerMAC = errors.New("it is signed in a way a newer version of Signalith uses")
)

// UnknownKeyError is a document signed with a cluster key this server
// does not hold.
type UnknownKeyError struct{ KID string }

func (e *UnknownKeyError) Error() string {
	return "it is signed with cluster key " + e.KID + ", which this server does not have"
}

var macForm = regexp.MustCompile(`^m[0-9]+:`)

// Verify checks the MAC of the document id against keys.
func Verify(keys *KeySet, id string, e *Envelope) error {
	if e.MAC == "" {
		return ErrNoMAC
	}
	rest, ok := strings.CutPrefix(e.MAC, macVersion+":")
	if !ok {
		if macForm.MatchString(e.MAC) {
			return ErrNewerMAC
		}
		return ErrBadMAC
	}
	kid, sum, ok := strings.Cut(rest, ":")
	if !ok {
		return ErrBadMAC
	}
	k := keys.Get(kid)
	if k == nil {
		return &UnknownKeyError{KID: kid}
	}
	got, err := base64.RawURLEncoding.DecodeString(sum)
	if err != nil {
		return ErrBadMAC
	}
	text, err := canonical(id, e)
	if err != nil {
		return ErrBadMAC
	}
	if !hmac.Equal(got, mac(k, text)) {
		return ErrBadMAC
	}
	return nil
}

// macKID returns the key id in a MAC, or "".
func macKID(m string) string {
	rest, ok := strings.CutPrefix(m, macVersion+":")
	if !ok {
		return ""
	}
	kid, _, _ := strings.Cut(rest, ":")
	return kid
}
