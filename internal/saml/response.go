package saml

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/jonboulle/clockwork"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// Assertion is who a checked response says signed in.
type Assertion struct {
	// ID is the assertion's ID, for the replay check.
	ID string
	// NameID is the subject's name at the provider, and NameIDFormat its
	// format.
	NameID       string
	NameIDFormat string
	// Expires is when the assertion can no longer be used; it is
	// remembered until then, so it is used once.
	Expires time.Time
	// Attributes are the values of each attribute, by its Name.
	Attributes map[string][]string
}

// Values returns the values of the attribute with exactly this Name. A
// FriendlyName, or another case, is not matched: it could pick another
// attribute than the one meant.
func (a *Assertion) Values(name string) []string { return a.Attributes[name] }

// Value returns the first value of attribute name, or "".
func (a *Assertion) Value(name string) string {
	if v := a.Values(name); len(v) > 0 {
		return v[0]
	}
	return ""
}

// Limits on what an assertion may carry.
const (
	maxAttributes = 200
	maxValues     = 1000
	maxValueLen   = 2048
)

// weakAlgorithms are the SHA-1 signature and digest methods, refused
// everywhere in a response.
var weakAlgorithms = map[string]bool{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":        true,
	"http://www.w3.org/2000/09/xmldsig#dsa-sha1":        true,
	"http://www.w3.org/2000/09/xmldsig#hmac-sha1":       true,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1": true,
	"http://www.w3.org/2000/09/xmldsig#sha1":            true,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-md5":    true,
	"http://www.w3.org/2001/04/xmldsig-more#md5":        true,
}

// ParseResponse checks a SAMLResponse (base64, as posted) from idp to sp,
// in answer to the request with ID requestID, at now, and returns the
// assertion in it. A response the provider refused wraps ErrDenied.
func ParseResponse(samlResponse string, idp *IdP, sp SP, requestID string, now time.Time) (*Assertion, error) {
	if idp == nil || len(idp.Certs) == 0 {
		return nil, errors.New("no identity provider is set up")
	}
	if requestID == "" {
		// Responses nobody here asked for (IdP-initiated) are refused:
		// nothing would tie them to this browser.
		return nil, errors.New("no sign-in is under way in this browser")
	}
	if len(samlResponse) > MaxResponse {
		return nil, fmt.Errorf("the response is larger than %d KB", MaxResponse>>10)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(samlResponse), ""))
	if err != nil {
		return nil, errors.New("the response is not base64")
	}
	doc, err := readXML(raw, MaxResponse)
	if err != nil {
		return nil, err
	}
	resp := doc.Root()
	if !is(resp, nsProtocol, "Response") {
		return nil, errors.New("this is not a SAML 2.0 Response")
	}
	if err := checkStructure(resp); err != nil {
		return nil, err
	}
	// Who answered, and to what. These are read before the signature is
	// checked only to refuse early with a useful reason; everything is
	// read again from the signed copy below.
	if err := checkResponse(resp, idp, sp, requestID, now); err != nil {
		return nil, err
	}

	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: idp.Certs})
	vc.Clock = dsig.NewFakeClock(clockwork.NewFakeClockAt(now))
	signed := false
	if sig, err := signatureOf(resp); err != nil {
		return nil, err
	} else if sig {
		if resp, err = validate(vc, resp); err != nil {
			return nil, fmt.Errorf("the response's signature is not valid: %w", err)
		}
		// Everything below reads the signed copy. Checked again, since a
		// signed response is what counts.
		if err := checkResponse(resp, idp, sp, requestID, now); err != nil {
			return nil, err
		}
		signed = true
	}
	as := children(resp, nsAssertion, "Assertion")
	if len(as) != 1 {
		return nil, fmt.Errorf("the response has %d assertions; it must have exactly one", len(as))
	}
	a := as[0]
	if sig, err := signatureOf(a); err != nil {
		return nil, err
	} else if sig {
		if a, err = validate(vc, a); err != nil {
			return nil, fmt.Errorf("the assertion's signature is not valid: %w", err)
		}
		signed = true
	}
	if !signed {
		return nil, errors.New("neither the response nor the assertion is signed; have the identity provider sign the assertion")
	}
	return readAssertion(a, idp, sp, requestID, now)
}

// checkStructure refuses what no honest response has: SHA-1 or MD5
// signatures and digests, an ID used twice (which signature wrapping
// relies on), more than one assertion anywhere, or an encrypted one.
func checkStructure(resp *etree.Element) error {
	for _, tag := range []string{"SignatureMethod", "DigestMethod"} {
		for _, m := range descendants(resp, dsig.Namespace, tag) {
			if weakAlgorithms[attr(m, "Algorithm")] {
				return fmt.Errorf("the response is signed with %s, which is too weak; have the identity provider use SHA-256", clip(attr(m, "Algorithm")))
			}
		}
	}
	ids := map[string]bool{}
	var dup error
	var walk func(*etree.Element)
	walk = func(e *etree.Element) {
		n := 0
		for _, a := range e.Attr {
			if a.Key == "ID" {
				n++
				if ids[a.Value] {
					dup = errors.New("the response uses an ID twice")
				}
				ids[a.Value] = true
			}
		}
		if n > 1 {
			dup = errors.New("an element of the response has two IDs")
		}
		for _, c := range e.ChildElements() {
			walk(c)
		}
	}
	walk(resp)
	if dup != nil {
		return dup
	}
	if len(descendants(resp, nsAssertion, "EncryptedAssertion")) > 0 {
		return errors.New("the assertion is encrypted, which Signalith does not support; turn assertion encryption off at the identity provider (the response travels over HTTPS)")
	}
	if n := len(descendants(resp, nsAssertion, "Assertion")); n > 1 {
		return fmt.Errorf("the response has %d assertions; it may have only one", n)
	}
	return nil
}

// signatureOf reports whether el has its own enveloped signature: a
// Signature child that refers to el's ID. Any other Signature child is
// refused.
func signatureOf(el *etree.Element) (bool, error) {
	sigs := children(el, dsig.Namespace, "Signature")
	switch len(sigs) {
	case 0:
		return false, nil
	case 1:
	default:
		return false, fmt.Errorf("the %s has %d signatures", el.Tag, len(sigs))
	}
	id := attr(el, "ID")
	if id == "" {
		return false, fmt.Errorf("the signed %s has no ID", el.Tag)
	}
	refs := descendants(sigs[0], dsig.Namespace, "Reference")
	if len(refs) != 1 || attr(refs[0], "URI") != "#"+id {
		return false, fmt.Errorf("the %s's signature does not refer to it alone", el.Tag)
	}
	return true, nil
}

// validate checks el's signature and returns the signed copy of el.
func validate(vc *dsig.ValidationContext, el *etree.Element) (*etree.Element, error) {
	// el, with the namespaces it inherits declared on it, as the
	// signature was made over it.
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, err
	}
	out, err := vc.Validate(detached)
	if err != nil {
		return nil, err
	}
	if out.Tag != el.Tag || out.NamespaceURI() != el.NamespaceURI() || attr(out, "ID") != attr(el, "ID") {
		return nil, errors.New("the signature covers something else")
	}
	return out, nil
}

// checkResponse checks the Response element itself: its version, that it
// answers this sign-in, at this address, from this provider, and that the
// provider said yes.
func checkResponse(resp *etree.Element, idp *IdP, sp SP, requestID string, now time.Time) error {
	if attr(resp, "Version") != "2.0" {
		return errors.New("the response is not SAML 2.0")
	}
	if attr(resp, "ID") == "" {
		return errors.New("the response has no ID")
	}
	if d := attr(resp, "Destination"); d != "" && d != sp.ACSURL {
		return fmt.Errorf("the response was sent to %q, not to Signalith's assertion consumer service %s", clip(d), sp.ACSURL)
	}
	if irt := attr(resp, "InResponseTo"); irt != requestID {
		if irt == "" {
			return errors.New("the response answers no sign-in request (IdP-initiated); start the sign-in from Signalith's sign-in page")
		}
		return errors.New("the response answers another sign-in, not the one under way in this browser")
	}
	if t, err := instant(resp, "IssueInstant"); err != nil {
		return err
	} else if t.After(now.Add(Skew)) {
		return errors.New("the response was issued in the future; check the clocks of Signalith and the identity provider")
	}
	if iss, err := child(resp, nsAssertion, "Issuer"); err != nil {
		return err
	} else if iss != nil {
		if err := checkIssuer(iss, idp); err != nil {
			return err
		}
	}
	st, err := child(resp, nsProtocol, "Status")
	if err != nil || st == nil {
		return errors.New("the response has no status")
	}
	code, err := child(st, nsProtocol, "StatusCode")
	if err != nil || code == nil {
		return errors.New("the response has no status code")
	}
	if v := attr(code, "Value"); v != statusSuccess {
		detail := strings.TrimPrefix(v, "urn:oasis:names:tc:SAML:2.0:status:")
		if sub, _ := child(code, nsProtocol, "StatusCode"); sub != nil {
			detail += " / " + strings.TrimPrefix(attr(sub, "Value"), "urn:oasis:names:tc:SAML:2.0:status:")
		}
		if m, _ := child(st, nsProtocol, "StatusMessage"); m != nil {
			if t, err := text(m); err == nil && t != "" {
				detail += ": " + t
			}
		}
		return fmt.Errorf("%w (%s)", ErrDenied, clip(detail))
	}
	return nil
}

func checkIssuer(iss *etree.Element, idp *IdP) error {
	if f := attr(iss, "Format"); f != "" && f != entityFormat {
		return errors.New("the issuer is not an entity ID")
	}
	v, err := text(iss)
	if err != nil {
		return err
	}
	if v != idp.EntityID {
		return fmt.Errorf("the issuer is %q, not the identity provider set up, %s", clip(v), idp.EntityID)
	}
	return nil
}

// readAssertion checks a signed assertion and reads it.
func readAssertion(a *etree.Element, idp *IdP, sp SP, requestID string, now time.Time) (*Assertion, error) {
	out := &Assertion{ID: attr(a, "ID"), Attributes: map[string][]string{}}
	if attr(a, "Version") != "2.0" || out.ID == "" {
		return nil, errors.New("the assertion is not SAML 2.0, or has no ID")
	}
	if t, err := instant(a, "IssueInstant"); err != nil {
		return nil, err
	} else if t.IsZero() || t.After(now.Add(Skew)) {
		return nil, errors.New("the assertion has no issue time, or was issued in the future; check the clocks of Signalith and the identity provider")
	}
	iss, err := child(a, nsAssertion, "Issuer")
	if err != nil {
		return nil, err
	}
	if iss == nil {
		return nil, errors.New("the assertion has no issuer")
	}
	if err := checkIssuer(iss, idp); err != nil {
		return nil, err
	}

	// Conditions: when, and for whom.
	cond, err := child(a, nsAssertion, "Conditions")
	if err != nil {
		return nil, err
	}
	if cond == nil {
		return nil, errors.New("the assertion has no conditions, so nothing says it is meant for Signalith")
	}
	nb, err := instant(cond, "NotBefore")
	if err != nil {
		return nil, err
	}
	na, err := instant(cond, "NotOnOrAfter")
	if err != nil {
		return nil, err
	}
	if !nb.IsZero() && now.Add(Skew).Before(nb) {
		return nil, errors.New("the assertion is not valid yet; check the clocks of Signalith and the identity provider")
	}
	if !na.IsZero() && !now.Add(-Skew).Before(na) {
		return nil, errors.New("the assertion has expired")
	}
	ars := children(cond, nsAssertion, "AudienceRestriction")
	if len(ars) == 0 {
		return nil, errors.New("the assertion names no audience, so nothing says it is meant for Signalith")
	}
	for _, ar := range ars {
		ok := false
		var seen []string
		for _, au := range children(ar, nsAssertion, "Audience") {
			v, err := text(au)
			if err != nil {
				return nil, err
			}
			seen = append(seen, v)
			if v == sp.EntityID {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("the assertion is meant for %q, not for Signalith (%s); set the identifier (entity ID) at the identity provider to Signalith's", clip(strings.Join(seen, ", ")), sp.EntityID)
		}
	}

	// The subject, and that this browser may present it.
	subj, err := child(a, nsAssertion, "Subject")
	if err != nil {
		return nil, err
	}
	if subj == nil {
		return nil, errors.New("the assertion has no subject")
	}
	if e, _ := child(subj, nsAssertion, "EncryptedID"); e != nil {
		return nil, errors.New("the subject's NameID is encrypted, which Signalith does not support")
	}
	nid, err := child(subj, nsAssertion, "NameID")
	if err != nil {
		return nil, err
	}
	if nid == nil {
		return nil, errors.New("the assertion has no NameID")
	}
	if out.NameID, err = text(nid); err != nil {
		return nil, err
	}
	if out.NameID == "" || len(out.NameID) > 512 {
		return nil, errors.New("the NameID is empty or too long")
	}
	out.NameIDFormat = attr(nid, "Format")
	confirmed := time.Time{}
	var why string
	for _, sc := range children(subj, nsAssertion, "SubjectConfirmation") {
		if attr(sc, "Method") != bearer {
			continue
		}
		d, err := child(sc, nsAssertion, "SubjectConfirmationData")
		if err != nil {
			return nil, err
		}
		if d == nil {
			why = "the bearer confirmation has no data"
			continue
		}
		exp, err := instant(d, "NotOnOrAfter")
		if err != nil {
			return nil, err
		}
		start, err := instant(d, "NotBefore")
		if err != nil {
			return nil, err
		}
		switch irt := attr(d, "InResponseTo"); {
		case attr(d, "Recipient") != sp.ACSURL:
			why = fmt.Sprintf("the assertion is for the address %q, not Signalith's assertion consumer service %s", clip(attr(d, "Recipient")), sp.ACSURL)
		case exp.IsZero():
			why = "the bearer confirmation has no expiry"
		case !now.Add(-Skew).Before(exp):
			why = "the assertion has expired"
		case !start.IsZero():
			why = "a bearer confirmation may not have a NotBefore"
		case irt != requestID:
			// Signed, unlike the response's own InResponseTo when only
			// the assertion is signed: this ties the assertion itself to
			// the sign-in under way in this browser.
			why = "the assertion answers another sign-in, or none"
		default:
			if exp.After(confirmed) {
				confirmed = exp
			}
		}
	}
	if confirmed.IsZero() {
		if why == "" {
			why = "the assertion has no bearer subject confirmation"
		}
		return nil, errors.New(why)
	}
	out.Expires = confirmed
	if na.After(out.Expires) {
		out.Expires = na
	}
	out.Expires = out.Expires.Add(Skew)

	// The provider must say the person signed in.
	as := children(a, nsAssertion, "AuthnStatement")
	if len(as) == 0 {
		return nil, errors.New("the assertion has no authentication statement")
	}
	for _, s := range as {
		if t, err := instant(s, "SessionNotOnOrAfter"); err != nil {
			return nil, err
		} else if !t.IsZero() && !now.Before(t) {
			return nil, errors.New("the session at the identity provider has ended")
		}
	}

	n := 0
	for _, st := range children(a, nsAssertion, "AttributeStatement") {
		for _, at := range children(st, nsAssertion, "Attribute") {
			if n++; n > maxAttributes {
				return nil, fmt.Errorf("the assertion has more than %d attributes", maxAttributes)
			}
			var vals []string
			for _, v := range children(at, nsAssertion, "AttributeValue") {
				t, err := text(v)
				if err != nil || t == "" {
					// A structured value: not one Signalith reads.
					continue
				}
				if len(vals) >= maxValues {
					return nil, fmt.Errorf("an attribute has more than %d values", maxValues)
				}
				if len(t) > maxValueLen {
					return nil, fmt.Errorf("an attribute value is longer than %d characters", maxValueLen)
				}
				vals = append(vals, t)
			}
			if name := attr(at, "Name"); name != "" {
				out.Attributes[name] = append(out.Attributes[name], vals...)
			}
		}
	}
	return out, nil
}
