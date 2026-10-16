package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Each server chains the audit records it writes, so that a record
// changed or removed in OpenSearch afterwards shows. Every record carries
// the hash of the record its server wrote before it (Prev), its place in
// the chain (Chain and Seq), and an HMAC-SHA256 of all its fields (MAC)
// made with a key derived from the cluster key (KID names which), which
// only the cluster's servers hold. Changing a record breaks its MAC;
// removing one leaves a gap in the sequence numbers and a Prev that
// matches nothing. The chain's head, the last record's sequence number and
// hash, is kept in the spool directory, so a restart continues the chain;
// a server that lost it starts a new chain, its first record marked
// ChainStart. Records the spool had to drop, or that OpenSearch refused,
// are named in an audit.lost record, so that their gap is told apart from
// a removal. See Verify.

// Actions of the records the chain itself makes.
const (
	ActionLost       = "audit.lost"
	ActionCheckpoint = "audit.checkpoint"
)

// Fields of an audit.lost record: how many records were lost, and the
// chain, first and last sequence number and the last hash of those that
// were chained.
const (
	fieldLost      = "lost"
	fieldLostChain = "lost_chain"
	fieldLostFrom  = "lost_from"
	fieldLostTo    = "lost_to"
	fieldLostHash  = "lost_hash"
)

// headPrefix starts the fields of an audit.checkpoint record, one for
// each server: head.<node_id> is "<chain>:<seq>:<hash>:<unix ms>" of the
// latest record of that server the checkpoint found.
const headPrefix = "head."

// chainFormat starts the canonical encoding a record's hash and MAC are
// made of; a later encoding gets another.
const chainFormat = "signalith audit chain v1\n"

// canonical is the encoding of a record its hash and MAC are made of:
// every field but the MAC, in a fixed order, with the time to the
// millisecond as OpenSearch keeps it. encoding/json writes struct fields
// in order and map keys sorted, so the same record always encodes the
// same.
func (e Event) canonical() []byte {
	fields := e.Fields
	if len(fields) == 0 {
		fields = nil
	}
	b, err := json.Marshal(struct {
		Time       string            `json:"t"`
		Server     string            `json:"server"`
		NodeID     string            `json:"node_id"`
		User       string            `json:"user"`
		Action     string            `json:"action"`
		Target     string            `json:"target"`
		Message    string            `json:"message"`
		SourceIP   string            `json:"source_ip"`
		Level      string            `json:"level"`
		Fields     map[string]string `json:"fields"`
		Epoch      int64             `json:"epoch"`
		Seq        int64             `json:"seq"`
		Chain      string            `json:"chain"`
		ChainStart bool              `json:"chain_start"`
		Prev       string            `json:"prev"`
		KID        string            `json:"kid"`
	}{stamp(e.Time), e.Server, e.NodeID, e.User, e.Action, e.Target, e.Message, e.SourceIP, e.Level, fields,
		e.Epoch, e.Seq, e.Chain, e.ChainStart, e.Prev, e.KID})
	if err != nil {
		// Strings and numbers always encode.
		panic(err)
	}
	return append([]byte(chainFormat), b...)
}

// stamp is the time as an audit document stores it.
func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// Hash returns the record's hash, as the next record of its chain names
// it in Prev: hex SHA-256 of its canonical encoding.
func (e Event) Hash() string {
	sum := sha256.Sum256(e.canonical())
	return hex.EncodeToString(sum[:])
}

// sign returns the record's MAC with key.
func (e Event) sign(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(e.canonical())
	return hex.EncodeToString(m.Sum(nil))
}

// checkMAC reports whether the record's MAC was made with key.
func (e Event) checkMAC(key []byte) bool {
	got, err := hex.DecodeString(e.MAC)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write(e.canonical())
	return hmac.Equal(got, m.Sum(nil))
}

// normalized returns ev as it reads back from JSON, with strings made
// valid UTF-8 as encoding/json makes them, so the hash and MAC made of it
// are the ones a reader of the spool or of OpenSearch computes.
func normalized(ev Event) (Event, error) {
	b, err := json.Marshal(ev)
	if err != nil {
		return ev, err
	}
	var out Event
	err = json.Unmarshal(b, &out)
	return out, err
}

// newChainID returns a new chain's ID: 16 random hex digits.
func newChainID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// The time is unique enough for a server's chains.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// chainHead is where a server's chain is: the last record's chain,
// sequence number and hash.
type chainHead struct {
	Format int    `json:"format"`
	NodeID string `json:"node_id"`
	Chain  string `json:"chain"`
	Seq    int64  `json:"seq"`
	Hash   string `json:"hash"`
}

// headFile is the chain head's file in the spool directory.
const headFile = "chain.json"

func readHead(dir string) (chainHead, error) {
	var h chainHead
	data, err := os.ReadFile(filepath.Join(dir, headFile))
	if err != nil {
		return h, err
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return chainHead{}, fmt.Errorf("%s: %w", headFile, err)
	}
	if h.Format != 1 || h.Chain == "" || h.Seq < 1 || len(h.Hash) != 64 {
		return chainHead{}, fmt.Errorf("%s: not a chain head", headFile)
	}
	return h, nil
}

// writeHead saves the chain head: written beside, then renamed over the
// old one, so a crash leaves one or the other. Where the rename fails
// (Windows, while something holds the file), it is written in place.
func writeHead(dir string, h chainHead) error {
	h.Format = 1
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, headFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return os.WriteFile(path, append(data, '\n'), 0o600)
	}
	return nil
}

// chainRef names one chained record: its chain, sequence number and hash.
type chainRef struct {
	node  string
	chain string
	seq   int64
	hash  string
}

// lostRange is a run of chained records that never reached OpenSearch.
type lostRange struct {
	chain    string
	from, to int64
	hash     string
	n        int64
	reason   string
}

// lostEvent returns the audit.lost record of r.
func lostEvent(r lostRange) Event {
	f := map[string]string{fieldLost: strconv.FormatInt(r.n, 10)}
	if r.chain != "" {
		f[fieldLostChain] = r.chain
		f[fieldLostFrom] = strconv.FormatInt(r.from, 10)
		f[fieldLostTo] = strconv.FormatInt(r.to, 10)
		f[fieldLostHash] = r.hash
	}
	return Event{Action: ActionLost, Message: "audit records lost: " + r.reason, Fields: f}
}

// KeyFunc returns the audit key with id kid (shared.ClusterKey.AuditKey),
// or nil when this server does not hold it.
type KeyFunc func(kid string) []byte
