package tlsauto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// How far Signalith's own certificate authority reaches
// (server.tls.ca_scope). Both keep it from ever vouching for public
// websites.
const (
	// ScopeStandard also lets it vouch for private network names and
	// addresses, so a new address for this server works right away.
	ScopeStandard = "standard"
	// ScopeStrict limits it to this server's names and addresses as they
	// were when it was made.
	ScopeStrict = "strict"
	// ScopeUnconstrained is a CA made by an older version, which may
	// vouch for any website.
	ScopeUnconstrained = "unconstrained"
)

// Folders and files of a change of certificate authority, in Options.Dir.
// A new CA is prepared in next/; after a switch, the one it replaced is
// kept in previous/ until it is removed, so Signalith can switch back.
// switch.json is the journal of a switch or a switch back in progress.
const (
	nextDir       = "next"
	previousDir   = "previous"
	discardedDir  = "discarded"
	journalFile   = "switch.json"
	stampMade     = "made_at"
	stampSwitched = "switched_at"
)

// StateError is a change of certificate authority that the present state
// does not allow, such as switching with no new one made. Its text says
// what to do instead.
type StateError struct{ msg string }

func (e *StateError) Error() string { return e.msg }

var (
	// ErrNotAuto: in files mode there is no certificate authority of
	// Signalith's own.
	ErrNotAuto = errors.New("Signalith uses your own certificate files, so it has no certificate authority of its own to change")
	// ErrNoNext: nothing was prepared.
	ErrNoNext = &StateError{"There's no new certificate authority to switch to."}
	// ErrNothingToCancel: nothing was prepared, so there is nothing to
	// discard.
	ErrNothingToCancel = &StateError{"There's no new certificate authority to cancel."}
	// ErrNextExists: one was prepared already.
	ErrNextExists = &StateError{"A new certificate authority is already made. Switch to it, or cancel it first."}
	// ErrPreviousKept: a new one cannot be made or switched to while the
	// one before is kept.
	ErrPreviousKept = &StateError{"Remove the previous certificate authority first, or switch back to it."}
	// ErrNoPrevious: there is nothing to switch back to or remove.
	ErrNoPrevious = &StateError{"There's no previous certificate authority."}
)

// CAInfo describes a certificate authority of Signalith's own.
type CAInfo struct {
	// Scope is ScopeStandard, ScopeStrict or ScopeUnconstrained.
	Scope       string    `json:"scope"`
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	// Names are this server's names and addresses in its constraints;
	// the private network names and ranges a standard one also allows
	// are left out.
	Names []string `json:"names"`
	// Subtrees are the names in Names whose names under them it also
	// allows: a CA made before Signalith excluded them (see
	// excludedSubtrees). Private network names are left out.
	Subtrees []string `json:"subtrees,omitempty"`
	// AnyUse means it is not limited to web servers (see caTemplate): one
	// made by an earlier version.
	AnyUse bool `json:"any_use,omitempty"`
	// At is when a prepared one was made, or when the switch away from a
	// kept one happened.
	At time.Time `json:"at,omitzero"`
}

// normScope returns ScopeStrict or ScopeStandard for a setting's value.
func normScope(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), ScopeStrict) {
		return ScopeStrict
	}
	return ScopeStandard
}

// classify says how far ca reaches: unconstrained when it has no name
// constraints, standard when they include a range wider than one address
// or private network names, strict otherwise.
func classify(ca *x509.Certificate) string {
	if len(ca.PermittedDNSDomains) == 0 && len(ca.PermittedIPRanges) == 0 {
		return ScopeUnconstrained
	}
	for _, r := range ca.PermittedIPRanges {
		if ones, bits := r.Mask.Size(); ones != bits {
			return ScopeStandard
		}
	}
	// A strict one has localhost, and may have a machine named like a
	// private suffix (such as "home"); a standard one has them all.
	private := 0
	for _, d := range ca.PermittedDNSDomains {
		if d = strings.ToLower(strings.TrimPrefix(d, ".")); d != "localhost" && slices.Contains(privateDomains, d) {
			private++
		}
	}
	if private >= 3 {
		return ScopeStandard
	}
	return ScopeStrict
}

// infoOf describes ca.
func infoOf(ca *x509.Certificate) *CAInfo {
	scope := classify(ca)
	in := &CAInfo{Scope: scope, Fingerprint: Fingerprint(ca.Raw), Subject: ca.Subject.CommonName,
		NotBefore: ca.NotBefore.UTC(), NotAfter: ca.NotAfter.UTC(), Names: []string{}, AnyUse: !ServerOnly(ca)}
	for _, d := range ca.PermittedDNSDomains {
		d = strings.ToLower(strings.TrimPrefix(d, "."))
		if d == "invalid" || scope == ScopeStandard && slices.Contains(privateDomains, d) {
			continue
		}
		in.Names = append(in.Names, d)
		if scope != ScopeUnconstrained && !domainAllowed(privateDomains, d) && !slices.ContainsFunc(ca.ExcludedDNSDomains, func(e string) bool {
			return strings.EqualFold(strings.TrimPrefix(e, "."), d)
		}) && !slices.ContainsFunc(ca.PermittedDNSDomains, func(o string) bool { return strings.HasSuffix(strings.ToLower(o), "."+d) }) {
			in.Subtrees = append(in.Subtrees, d)
		}
	}
	for _, r := range ca.PermittedIPRanges {
		ones, bits := r.Mask.Size()
		a, ok := netip.AddrFromSlice(r.IP)
		if !ok || ones != bits || a.Unmap() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			continue
		}
		a = a.Unmap()
		if scope == ScopeStandard && slices.ContainsFunc(privateRanges, func(p netip.Prefix) bool { return p.Contains(a) }) {
			continue
		}
		in.Names = append(in.Names, a.String())
	}
	return in
}

// CAInfo describes the certificate authority in use, or returns nil in
// files mode.
func (m *Manager) CAInfo() *CAInfo {
	if !m.LocalCA() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ca == nil {
		return nil
	}
	return infoOf(m.ca)
}

// Next describes the certificate authority Prepare made, not used yet,
// or returns nil when there is none.
func (m *Manager) Next() *CAInfo {
	if !m.LocalCA() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.infoIn(nextDir, stampMade)
}

// Previous describes the certificate authority a switch replaced, kept
// until Prune, or returns nil when there is none.
func (m *Manager) Previous() *CAInfo {
	if !m.LocalCA() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.infoIn(previousDir, stampSwitched)
}

func (m *Manager) infoIn(dir, stamp string) *CAInfo {
	b, err := os.ReadFile(m.path(dir, CAFile))
	if err != nil {
		return nil
	}
	ca, err := parseCert(b)
	if err != nil {
		return nil
	}
	in := infoOf(ca)
	in.At = readStamp(m.path(dir, stamp))
	return in
}

// NextPEM returns the prepared certificate authority, in PEM, or nil.
func (m *Manager) NextPEM() []byte {
	if !m.LocalCA() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nextPEMLocked()
}

func (m *Manager) nextPEMLocked() []byte {
	b, err := os.ReadFile(m.path(nextDir, CAFile))
	if err != nil {
		return nil
	}
	ca, err := parseCert(b)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
}

// AgentCAPEM is the CA file agents and syslog devices should get: while a
// new certificate authority is prepared, the one in use and the new one
// together, so they keep working after the switch; otherwise CAPEM.
func (m *Manager) AgentCAPEM() []byte {
	cur := m.CAPEM()
	if cur == nil || !m.LocalCA() {
		return cur
	}
	next := m.NextPEM()
	if next == nil {
		return cur
	}
	return append(append(slices.Clone(cur), '\n'), next...)
}

// WouldCover lists the names a certificate authority made now with scope
// would let the certificate cover: every name the certificate should
// have (the public_url host, server.tls.names, this machine's names and
// addresses, and the ones Add data added). A standard one also allows
// any private network name or address.
func (m *Manager) WouldCover(scope string) []string {
	if !m.LocalCA() {
		return nil
	}
	_ = scope // both cover every name the certificate should have
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.candidateNames()
}

// WouldAllow reports whether a certificate authority made now with scope
// could vouch for name.
func (m *Manager) WouldAllow(scope, name string) bool {
	n, ok := normalizeName(name)
	if !ok || !m.LocalCA() {
		return false
	}
	m.mu.Lock()
	names := m.candidateNames()
	m.mu.Unlock()
	dns, excluded, ips := constraints(names, normScope(scope) == ScopeStrict)
	tmpl := &x509.Certificate{PermittedDNSDomains: dns, ExcludedDNSDomains: excluded, PermittedIPRanges: ips}
	return caAllows(tmpl, n)
}

// Prepare makes a new certificate authority with scope (ScopeStandard or
// ScopeStrict) for the names the certificate should cover now, next to
// the one in use, which keeps working. Nothing changes for browsers or
// agents until Switch.
func (m *Manager) Prepare(scope string) error {
	if !m.LocalCA() {
		return ErrNotAuto
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Under the lock, so it cannot race UseStore.
	if m.inCluster() {
		return ErrClusterCA
	}
	if exists(m.path(previousDir)) {
		return ErrPreviousKept
	}
	if exists(m.path(nextDir, CAFile)) {
		return ErrNextExists
	}
	scope = normScope(scope)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "signalith"
	}
	now := m.now()
	dns, excluded, ips := constraints(m.candidateNames(), scope == ScopeStrict)
	tmpl := caTemplate("Signalith Local CA ("+host+", "+now.UTC().Format(time.DateOnly)+")", now, dns, excluded, ips)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	dir := m.path(nextDir)
	fail := func(err error) error {
		_ = os.RemoveAll(dir)
		return err
	}
	if err := securefile.MkdirPrivate(dir); err != nil {
		return fail(fmt.Errorf("cannot create %s: %w", dir, err))
	}
	if err := writeCAKey(filepath.Join(dir, caKeyFile), key); err != nil {
		return fail(err)
	}
	if err := writeFile(filepath.Join(dir, CAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return fail(err)
	}
	if err := writeStamp(filepath.Join(dir, stampMade), now); err != nil {
		return fail(err)
	}
	m.log().Info("made a new certificate authority for HTTPS; it is used once you switch to it on the Security page",
		"scope", scope, "ca_sha256", Fingerprint(der), "ca_file", filepath.Join(dir, CAFile))
	return nil
}

// Discard removes the prepared certificate authority.
func (m *Manager) Discard() error {
	if !m.LocalCA() {
		return ErrNotAuto
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Under the lock, so it cannot race UseStore.
	if m.inCluster() {
		return ErrClusterCA
	}
	if !exists(m.path(nextDir)) {
		return ErrNothingToCancel
	}
	if err := os.RemoveAll(m.path(nextDir)); err != nil {
		return err
	}
	m.log().Info("removed the new certificate authority that was not switched to")
	return nil
}

// Prune removes the certificate authority kept after a switch. Switching
// back is not possible after this.
func (m *Manager) Prune() error {
	if !m.LocalCA() {
		return ErrNotAuto
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Under the lock, so it cannot race UseStore.
	if m.inCluster() {
		return ErrClusterCA
	}
	if !exists(m.path(previousDir)) {
		return ErrNoPrevious
	}
	if err := os.RemoveAll(m.path(previousDir)); err != nil {
		return err
	}
	m.switchedAt = time.Time{}
	m.seen.reset()
	m.log().Info("removed the previous certificate authority")
	return nil
}

// Switch makes the prepared certificate authority the one in use, with a
// new certificate from it, and keeps the one it replaces in previous/ so
// Rollback can go back. It happens in place: new HTTPS and syslog over
// TLS connections get the new certificate at once, and connections open
// now finish on the old one. A journal lets the next start finish or undo
// a switch a crash cut short.
func (m *Manager) Switch() error {
	if !m.LocalCA() {
		return ErrNotAuto
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Under the lock, so it cannot race UseStore.
	if m.inCluster() {
		return ErrClusterCA
	}
	if !exists(m.path(nextDir, CAFile)) {
		return ErrNoNext
	}
	if exists(m.path(previousDir)) {
		return ErrPreviousKept
	}
	nextCA, nextKey, err := readPair(m.path(nextDir))
	if err != nil {
		return err
	}
	j := &journal{Op: "switch", From: Fingerprint(m.ca.Raw), To: Fingerprint(nextCA.Raw), At: m.now().UTC()}
	if err := m.plan(j, [][2]string{
		{CAFile, previousDir + "/" + CAFile}, {caKeyFile, previousDir + "/" + caKeyFile},
		{certFile, previousDir + "/" + certFile}, {keyFile, previousDir + "/" + keyFile},
		{nextDir + "/" + CAFile, CAFile}, {nextDir + "/" + caKeyFile, caKeyFile},
	}); err != nil {
		return err
	}
	if err := m.writeJournal(j); err != nil {
		return err
	}
	oldCA, oldKey := m.ca, m.caKey
	fail := func(err error) error {
		if crashed(err) {
			return err
		}
		m.ca, m.caKey = oldCA, oldKey
		if uerr := m.undo(j); uerr != nil {
			return fmt.Errorf("could not switch certificate authority (%w), nor put the files back (%v); restart Signalith, which finishes or undoes the switch", err, uerr)
		}
		m.wantNames()
		return fmt.Errorf("could not switch certificate authority, so the one in use stays: %w", err)
	}
	if err := m.runMoves(j); err != nil {
		return fail(err)
	}
	m.ca, m.caKey = nextCA, nextKey
	leaf, err := m.issueLeaf()
	if err != nil {
		return fail(err)
	}
	if err := checkpoint("leaf"); err != nil {
		return fail(err)
	}
	// To the second, as the stamp keeps it.
	now := m.now().UTC().Truncate(time.Second)
	if err := writeStamp(m.path(previousDir, stampSwitched), now); err != nil {
		return fail(err)
	}
	if err := checkpoint("stamp"); err != nil {
		return fail(err)
	}
	_ = os.RemoveAll(m.path(nextDir))
	_ = os.Remove(m.path(journalFile))
	m.cert.Store(leaf)
	m.switchedAt = now
	m.seen.reset()
	m.log().Info("switched to the new certificate authority for HTTPS; the previous one is kept until you remove it on the Security page",
		"from_sha256", j.From, "to_sha256", j.To, "names", strings.Join(certNames(leaf.Leaf), ","))
	return nil
}

// Rollback goes back to the certificate authority a switch replaced. The
// one in use goes back to next/, so switching again later needs no new
// sharing.
func (m *Manager) Rollback() error {
	if !m.LocalCA() {
		return ErrNotAuto
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Under the lock, so it cannot race UseStore.
	if m.inCluster() {
		return ErrClusterCA
	}
	if !exists(m.path(previousDir, CAFile)) {
		return ErrNoPrevious
	}
	if exists(m.path(nextDir)) {
		return &StateError{"Cancel the new certificate authority first."}
	}
	prevCA, prevKey, err := readPair(m.path(previousDir))
	if err != nil {
		return err
	}
	j := &journal{Op: "rollback", From: Fingerprint(m.ca.Raw), To: Fingerprint(prevCA.Raw), At: m.now().UTC()}
	if err := m.plan(j, [][2]string{
		{CAFile, nextDir + "/" + CAFile}, {caKeyFile, nextDir + "/" + caKeyFile},
		{certFile, discardedDir + "/" + certFile}, {keyFile, discardedDir + "/" + keyFile},
		{previousDir + "/" + CAFile, CAFile}, {previousDir + "/" + caKeyFile, caKeyFile},
		{previousDir + "/" + certFile, certFile}, {previousDir + "/" + keyFile, keyFile},
	}); err != nil {
		return err
	}
	if err := m.writeJournal(j); err != nil {
		return err
	}
	oldCA, oldKey := m.ca, m.caKey
	fail := func(err error) error {
		if crashed(err) {
			return err
		}
		m.ca, m.caKey = oldCA, oldKey
		if uerr := m.undo(j); uerr != nil {
			return fmt.Errorf("could not switch back (%w), nor put the files back (%v); restart Signalith, which finishes or undoes the switch", err, uerr)
		}
		m.wantNames()
		return fmt.Errorf("could not switch back, so the certificate authority in use stays: %w", err)
	}
	if err := m.runMoves(j); err != nil {
		return fail(err)
	}
	m.ca, m.caKey = prevCA, prevKey
	leaf, err := m.servedLeaf()
	if err != nil {
		return fail(err)
	}
	if err := writeStamp(m.path(nextDir, stampMade), m.now()); err != nil {
		return fail(err)
	}
	_ = os.RemoveAll(m.path(previousDir))
	_ = os.RemoveAll(m.path(discardedDir))
	_ = os.Remove(m.path(journalFile))
	m.cert.Store(leaf)
	m.switchedAt = time.Time{}
	m.seen.reset()
	m.log().Info("switched back to the previous certificate authority for HTTPS; the newer one is kept, ready to switch to again",
		"from_sha256", j.From, "to_sha256", j.To)
	return nil
}

// servedLeaf is the certificate in the folder when it is from the CA in
// use and still good, or a new one. The caller holds m.mu.
func (m *Manager) servedLeaf() (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(m.path(certFile), m.path(keyFile))
	if err == nil && m.usable(pair.Leaf) {
		return &pair, nil
	}
	return m.issueLeaf()
}

// ---- the journal ----

// journal records a switch or switch back while it happens: the files it
// moves, each with the SHA-256 of its content, so a later start can tell
// which moves were done and finish or undo them.
type journal struct {
	Op    string    `json:"op"` // switch or rollback
	From  string    `json:"from"`
	To    string    `json:"to"`
	At    time.Time `json:"at"`
	Moves []move    `json:"moves"`
}

// move is one file moved, with paths relative to the tls folder, written
// with forward slashes.
type move struct {
	From   string `json:"from"`
	To     string `json:"to"`
	SHA256 string `json:"sha256"`
}

// plan fills j.Moves with the moves whose source exists.
func (m *Manager) plan(j *journal, moves [][2]string) error {
	for _, mv := range moves {
		sum, err := fileSum(m.rel(mv[0]))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		j.Moves = append(j.Moves, move{From: mv[0], To: mv[1], SHA256: sum})
	}
	return nil
}

func (m *Manager) rel(p string) string { return filepath.Join(m.opts.Dir, filepath.FromSlash(p)) }

// rename is os.Rename; tests make it fail.
var rename = os.Rename

// testCrash, set by tests, stops a switch at a checkpoint as a crash
// would, leaving everything as it is; nil in use.
var testCrash func(point string) bool

// errCrash is a switch stopped by testCrash, which leaves everything as a
// crash would.
var errCrash = errors.New("stopped as if Signalith crashed")

func checkpoint(point string) error {
	if testCrash != nil && testCrash(point) {
		return errCrash
	}
	return nil
}

func crashed(err error) bool { return errors.Is(err, errCrash) }

func (m *Manager) runMoves(j *journal) error {
	for i, mv := range j.Moves {
		if err := checkpoint(fmt.Sprintf("move:%d", i)); err != nil {
			return err
		}
		to := m.rel(mv.To)
		if err := securefile.MkdirPrivate(filepath.Dir(to)); err != nil {
			return err
		}
		if err := rename(m.rel(mv.From), to); err != nil {
			return err
		}
	}
	return nil
}

// done reports whether mv was made: its destination holds the file.
func (m *Manager) done(mv move) bool {
	sum, err := fileSum(m.rel(mv.To))
	return err == nil && sum == mv.SHA256
}

// undo moves back, last first, the files j moved, and removes the
// folders it made, then the journal.
func (m *Manager) undo(j *journal) error {
	for i := len(j.Moves) - 1; i >= 0; i-- {
		mv := j.Moves[i]
		if !m.done(mv) {
			continue
		}
		from := m.rel(mv.From)
		if err := securefile.MkdirPrivate(filepath.Dir(from)); err != nil {
			return err
		}
		if err := os.Rename(m.rel(mv.To), from); err != nil {
			return err
		}
	}
	// The folders the operation made, which did not exist before it.
	made := []string{previousDir}
	if j.Op == "rollback" {
		made = []string{nextDir, discardedDir}
	}
	for _, d := range made {
		if err := os.RemoveAll(m.path(d)); err != nil {
			return err
		}
	}
	return os.Remove(m.path(journalFile))
}

// writeJournal writes j where the next start finds it, and syncs it to
// disk first.
func (m *Manager) writeJournal(j *journal) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	p := m.path(journalFile)
	f, err := os.CreateTemp(m.opts.Dir, "."+journalFile+"-*")
	if err != nil {
		return fmt.Errorf("cannot write %s: %w", p, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("cannot write %s: %w", p, err)
	}
	return checkpoint("journal")
}

// recoverSwitch finishes or undoes a switch, or a switch back, that a
// crash cut short: finished when every file was moved and the folder
// holds the new certificate authority with a certificate from it,
// undone otherwise.
func (m *Manager) recoverSwitch() error {
	b, err := os.ReadFile(m.path(journalFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", m.path(journalFile), err)
	}
	var j journal
	if err := json.Unmarshal(b, &j); err != nil || (j.Op != "switch" && j.Op != "rollback") {
		return fmt.Errorf("%s is damaged, so Signalith cannot tell whether a switch of certificate authority finished. "+
			"Move it away and check that ca.pem and ca.key in %s belong together", m.path(journalFile), m.opts.Dir)
	}
	all := true
	for _, mv := range j.Moves {
		if !m.done(mv) {
			all = false
		}
	}
	complete := all && m.caFingerprint() == j.To
	if complete && j.Op == "switch" {
		complete = m.leafChains()
	}
	if !complete {
		if err := m.undo(&j); err != nil {
			return fmt.Errorf("could not undo an unfinished switch of certificate authority: %w", err)
		}
		if j.Op == "switch" {
			m.log().Warn("An unfinished switch of certificate authority was undone; the previous one is in use.")
		} else {
			m.log().Warn("An unfinished switch back to the previous certificate authority was undone; the newer one is in use.")
		}
		return nil
	}
	if j.Op == "switch" {
		if readStamp(m.path(previousDir, stampSwitched)).IsZero() {
			if err := writeStamp(m.path(previousDir, stampSwitched), j.At); err != nil {
				return err
			}
		}
		_ = os.RemoveAll(m.path(nextDir))
	} else {
		if readStamp(m.path(nextDir, stampMade)).IsZero() {
			if err := writeStamp(m.path(nextDir, stampMade), j.At); err != nil {
				return err
			}
		}
		_ = os.RemoveAll(m.path(previousDir))
		_ = os.RemoveAll(m.path(discardedDir))
	}
	m.log().Info("finished a switch of certificate authority that was cut short", "op", j.Op, "to_sha256", j.To)
	return os.Remove(m.path(journalFile))
}

// caFingerprint is the fingerprint of ca.pem in the folder, or "".
func (m *Manager) caFingerprint() string {
	b, err := os.ReadFile(m.path(CAFile))
	if err != nil {
		return ""
	}
	ca, err := parseCert(b)
	if err != nil {
		return ""
	}
	return Fingerprint(ca.Raw)
}

// leafChains reports whether server.pem in the folder is signed by
// ca.pem there.
func (m *Manager) leafChains() bool {
	cb, err := os.ReadFile(m.path(CAFile))
	if err != nil {
		return false
	}
	ca, err := parseCert(cb)
	if err != nil {
		return false
	}
	lb, err := os.ReadFile(m.path(certFile))
	if err != nil {
		return false
	}
	leaf, err := parseCert(lb)
	return err == nil && leaf.CheckSignatureFrom(ca) == nil
}

// readPair reads ca.pem and ca.key in dir and checks they belong
// together.
func readPair(dir string) (*x509.Certificate, crypto.Signer, error) {
	b, err := os.ReadFile(filepath.Join(dir, CAFile))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read %s: %w", filepath.Join(dir, CAFile), err)
	}
	ca, err := parseCert(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", filepath.Join(dir, CAFile), err)
	}
	key, err := readCAKey(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, nil, err
	}
	if !samePublicKey(ca.PublicKey, key.Public()) {
		return nil, nil, fmt.Errorf("%s does not belong to %s", filepath.Join(dir, caKeyFile), filepath.Join(dir, CAFile))
	}
	return ca, key, nil
}

func fileSum(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// readStamp reads a time written by writeStamp, or returns zero.
func readStamp(p string) time.Time {
	b, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func writeStamp(p string, t time.Time) error {
	return writeFile(p, []byte(t.UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// ---- who refused the new certificate, and the names people use ----

// Refusal is a computer that refused the certificate since the last
// switch of certificate authority.
type Refusal struct {
	Address  string    `json:"address"`
	Via      string    `json:"via"` // https or syslog
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

// SeenName is a host name or address someone used to reach this server.
type SeenName struct {
	Name     string    `json:"name"`
	LastSeen time.Time `json:"last_seen"`
}

// Most addresses and names kept, in memory only.
const (
	maxRefusals = 200
	maxSeen     = 50
)

// recorder keeps a few recent entries by address and way in, dropping
// the oldest.
type recorder struct {
	mu sync.Mutex
	m  map[string]*Refusal
}

func (r *recorder) note(addr, via string, at time.Time, limit int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string]*Refusal{}
	}
	// One computer may refuse over HTTPS and over syslog: each is its own
	// entry, so neither hides the other.
	key := addr + "\x00" + via
	e := r.m[key]
	if e == nil {
		if len(r.m) >= limit {
			oldest := ""
			for k, v := range r.m {
				if oldest == "" || v.LastSeen.Before(r.m[oldest].LastSeen) {
					oldest = k
				}
			}
			delete(r.m, oldest)
		}
		e = &Refusal{Address: addr, Via: via}
		r.m[key] = e
	}
	e.LastSeen = at.UTC()
	e.Count++
}

func (r *recorder) list(since time.Time) []Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Refusal{}
	for _, v := range r.m {
		if !v.LastSeen.Before(since) {
			out = append(out, *v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].Via < out[j].Via
	})
	return out
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.m = nil
	r.mu.Unlock()
}

// NoteRefusal records that the computer at addr (host:port or an
// address) refused this server's certificate, over via (https or
// syslog). Only refusals since a switch of certificate authority, while
// the previous one is kept, are recorded: they are the computers that do
// not trust the new one yet.
func (m *Manager) NoteRefusal(addr, via string) {
	if m == nil || !m.LocalCA() {
		return
	}
	m.mu.Lock()
	switched := !m.switchedAt.IsZero()
	m.mu.Unlock()
	if !switched {
		return
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	m.seen.note(a.Unmap().String(), via, m.now(), maxRefusals)
}

// Refusals lists the computers that refused the certificate since the
// last switch, newest first.
func (m *Manager) Refusals() []Refusal {
	if m == nil {
		return []Refusal{}
	}
	return m.seen.list(time.Time{})
}

// SwitchedAt is when Signalith last switched certificate authority while
// the previous one is kept, or zero.
func (m *Manager) SwitchedAt() time.Time {
	if m == nil {
		return time.Time{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.switchedAt
}

// NoteName records a host name or address someone used to reach this
// server: the host of a request, or the name a client asked for in the
// TLS handshake. Callers note only names from clients that proved they
// may use the server (signed in, sent an agent token, or sent syslog from
// an allowed address), so a stranger can't fill the list.
func (m *Manager) NoteName(host string) {
	if m == nil {
		return
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	n, ok := normalizeName(host)
	if !ok {
		return
	}
	m.names.note(n, "", m.now(), maxSeen)
}

// SeenNames lists the names noted in the last day, newest first.
func (m *Manager) SeenNames() []SeenName {
	if m == nil {
		return []SeenName{}
	}
	out := []SeenName{}
	for _, e := range m.names.list(m.now().Add(-24 * time.Hour)) {
		out = append(out, SeenName{Name: e.Address, LastSeen: e.LastSeen})
	}
	return out
}
