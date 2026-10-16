// Package scim reads and writes the parts of SCIM 2.0 (RFC 7643 and RFC
// 7644) that identity providers such as Microsoft Entra ID and Okta use to
// provision users into an application: the User resource, the filters
// they look users up with, and the PATCH operations they change users
// with. Both providers bend the standard a little (Entra ID sends
// "Replace" and "False", Okta a PATCH with no path), and this package
// takes what they send.
//
// It knows nothing of Signalith's users; the API maps a User to them.
package scim

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Schemas and message URNs.
const (
	UserSchema       = "urn:ietf:params:scim:schemas:core:2.0:User"
	EnterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	ListSchema       = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	PatchSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ErrorSchema      = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// ContentType is the media type of SCIM requests and answers.
const ContentType = "application/scim+json"

// Name is a User's name.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// Email is one of a User's email addresses.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Meta is a resource's metadata.
type Meta struct {
	ResourceType string     `json:"resourceType"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
	Version      string     `json:"version,omitempty"`
}

// User is a SCIM User resource, with the attributes Signalith keeps.
// Others a provider sends are ignored.
type User struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	Name        *Name    `json:"name,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Emails      []Email  `json:"emails,omitempty"`
	Active      bool     `json:"active"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// FullName is the name to show: displayName, else name.formatted, else
// the given and family names.
func (u *User) FullName() string {
	if s := strings.TrimSpace(u.DisplayName); s != "" {
		return s
	}
	if u.Name == nil {
		return ""
	}
	if s := strings.TrimSpace(u.Name.Formatted); s != "" {
		return s
	}
	return strings.TrimSpace(u.Name.GivenName + " " + u.Name.FamilyName)
}

// PrimaryEmail is the address to keep: the primary one, else the work
// one, else the first.
func (u *User) PrimaryEmail() string {
	for _, e := range u.Emails {
		if e.Primary {
			return strings.TrimSpace(e.Value)
		}
	}
	for _, e := range u.Emails {
		if strings.EqualFold(e.Type, "work") {
			return strings.TrimSpace(e.Value)
		}
	}
	if len(u.Emails) > 0 {
		return strings.TrimSpace(u.Emails[0].Value)
	}
	return ""
}

// SetEmail makes v the primary address, or removes every address when v
// is empty.
func (u *User) SetEmail(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		u.Emails = nil
		return
	}
	u.Emails = []Email{{Value: v, Type: "work", Primary: true}}
}

// Error is a SCIM error answer. ScimType is one of RFC 7644's, such as
// invalidFilter, invalidValue, uniqueness or mutability.
type Error struct {
	Status   int
	ScimType string
	Detail   string
}

func (e *Error) Error() string { return e.Detail }

// MarshalJSON writes the error as RFC 7644 section 3.12 has it.
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Schemas  []string `json:"schemas"`
		Status   string   `json:"status"`
		ScimType string   `json:"scimType,omitempty"`
		Detail   string   `json:"detail,omitempty"`
	}{[]string{ErrorSchema}, fmt.Sprint(e.Status), e.ScimType, e.Detail})
}

func badValue(format string, args ...any) *Error {
	return &Error{Status: 400, ScimType: "invalidValue", Detail: fmt.Sprintf(format, args...)}
}

func badSyntax(format string, args ...any) *Error {
	return &Error{Status: 400, ScimType: "invalidSyntax", Detail: fmt.Sprintf(format, args...)}
}

// MaxBody is the largest request body read.
const MaxBody = 64 << 10

// DecodeUser reads a User from a POST or PUT body. Attribute names are
// matched without regard to case, as RFC 7643 says, and active may be a
// string ("True") as some providers send it. A missing active is true.
func DecodeUser(body []byte) (User, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return User{}, badSyntax("the body is not a JSON object: %v", err)
	}
	u := User{Active: true}
	for _, k := range sortedKeys(raw) {
		if err := u.set(attrName(k), raw[k], false); err != nil {
			return User{}, err
		}
	}
	return u, nil
}

// attrName returns an attribute path without the core User schema's URN
// in front, in lower case.
func attrName(p string) string {
	p = strings.TrimSpace(p)
	if len(p) > len(UserSchema)+1 && strings.EqualFold(p[:len(UserSchema)+1], UserSchema+":") {
		p = p[len(UserSchema)+1:]
	}
	return strings.ToLower(p)
}

// set changes the attribute name (lower case, without the schema URN) to
// the JSON value v. remove clears it instead. Attributes Signalith does
// not keep are ignored.
func (u *User) set(name string, v json.RawMessage, remove bool) error {
	str := func(dst *string) error {
		if remove {
			*dst = ""
			return nil
		}
		s, err := stringOf(name, v)
		if err != nil {
			return err
		}
		*dst = s
		return nil
	}
	name1 := func() *Name {
		if u.Name == nil {
			u.Name = &Name{}
		}
		return u.Name
	}
	switch name {
	case "username":
		return str(&u.UserName)
	case "externalid":
		return str(&u.ExternalID)
	case "displayname":
		return str(&u.DisplayName)
	case "name.formatted":
		return str(&name1().Formatted)
	case "name.givenname":
		return str(&name1().GivenName)
	case "name.familyname":
		return str(&name1().FamilyName)
	case "name":
		if remove {
			u.Name = nil
			return nil
		}
		if isNull(v) {
			u.Name = nil
			return nil
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(v, &m); err != nil {
			return badValue("name must be an object")
		}
		for _, k := range sortedKeys(m) {
			if err := u.set("name."+strings.ToLower(k), m[k], false); err != nil {
				return err
			}
		}
		return nil
	case "active":
		if remove {
			return nil
		}
		b, err := boolOf(v)
		if err != nil {
			return err
		}
		u.Active = b
		return nil
	case "emails":
		if remove || isNull(v) {
			u.Emails = nil
			return nil
		}
		var list []map[string]json.RawMessage
		if err := json.Unmarshal(v, &list); err != nil {
			return badValue("emails must be a list of objects")
		}
		u.Emails = nil
		for _, m := range list {
			var e Email
			for k, sub := range m {
				var err error
				switch strings.ToLower(k) {
				case "value":
					e.Value, err = stringOf("emails.value", sub)
				case "type":
					e.Type, err = stringOf("emails.type", sub)
				case "primary":
					e.Primary, err = boolOf(sub)
				}
				if err != nil {
					return err
				}
			}
			u.Emails = append(u.Emails, e)
		}
		return nil
	case "schemas", "id", "meta":
		// Read-only, or the server's.
		return nil
	}
	if strings.HasPrefix(name, "emails[") {
		// emails[type eq "work"].value, as Entra ID sends it: the address
		// to keep.
		if !strings.HasSuffix(name, "].value") {
			return nil
		}
		if remove {
			u.Emails = nil
			return nil
		}
		s, err := stringOf("emails.value", v)
		if err != nil {
			return err
		}
		u.SetEmail(s)
		return nil
	}
	return nil
}

// sortedKeys returns m's keys in order, so the same request always makes
// the same change: "name" comes before "name.givenName".
func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isNull(v json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(v), []byte("null")) }

// stringOf reads a JSON string; null is "".
func stringOf(name string, v json.RawMessage) (string, error) {
	if isNull(v) {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", badValue("%s must be a string", name)
	}
	return s, nil
}

// boolOf reads a JSON boolean, or a string that is one ("True", "false").
func boolOf(v json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(v, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, badValue("active must be true or false")
}

// ---- filters ----

// Filter is a list request's filter: attribute eq value. Attr is lower
// case: username, externalid, id or emails.value.
type Filter struct {
	Attr  string
	Value string
}

// ErrFilter refuses a filter this package does not read.
var ErrFilter = errors.New(`only filters like userName eq "alice" are supported, on userName, externalId, id or emails.value`)

// ParseFilter reads a filter such as userName eq "alice@example.com",
// which is what Entra ID and Okta send to find a user before they add
// one. An empty filter is the zero Filter.
func ParseFilter(s string) (Filter, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Filter{}, nil
	}
	if len(s) > 1024 {
		return Filter{}, ErrFilter
	}
	attr, rest, ok := strings.Cut(s, " ")
	if !ok {
		return Filter{}, ErrFilter
	}
	op, val, ok := strings.Cut(strings.TrimLeftFunc(rest, unicode.IsSpace), " ")
	if !ok || !strings.EqualFold(op, "eq") {
		return Filter{}, ErrFilter
	}
	val = strings.TrimSpace(val)
	var v string
	if err := json.Unmarshal([]byte(val), &v); err != nil {
		return Filter{}, ErrFilter
	}
	f := Filter{Attr: attrName(attr), Value: v}
	switch f.Attr {
	case "username", "externalid", "id", "emails.value", "emails":
		if f.Attr == "emails" {
			f.Attr = "emails.value"
		}
		return f, nil
	}
	return Filter{}, ErrFilter
}

// Match reports whether u passes the filter. userName and emails compare
// without regard to case, as RFC 7643 has them; externalId and id are
// exact.
func (f Filter) Match(u *User) bool {
	switch f.Attr {
	case "":
		return true
	case "username":
		return strings.EqualFold(u.UserName, f.Value)
	case "externalid":
		return u.ExternalID == f.Value
	case "id":
		return u.ID == f.Value
	case "emails.value":
		for _, e := range u.Emails {
			if strings.EqualFold(e.Value, f.Value) {
				return true
			}
		}
	}
	return false
}

// ---- PATCH ----

// Op is one PATCH operation.
type Op struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// MaxOps is the most operations one PATCH may hold.
const MaxOps = 100

// DecodePatch reads a PATCH body's operations.
func DecodePatch(body []byte) ([]Op, error) {
	var req struct {
		Operations []Op `json:"Operations"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, badSyntax("the body is not a SCIM PATCH request: %v", err)
	}
	if len(req.Operations) == 0 {
		return nil, badSyntax("the PATCH request has no Operations")
	}
	if len(req.Operations) > MaxOps {
		return nil, badSyntax("a PATCH request may hold at most %d operations", MaxOps)
	}
	return req.Operations, nil
}

// Apply makes the operations' changes to u. add and replace set an
// attribute (or, with no path, every attribute in the value's object);
// remove clears it. Attributes Signalith does not keep, such as the
// enterprise extension's, are ignored.
func Apply(u *User, ops []Op) error {
	for _, op := range ops {
		kind := strings.ToLower(strings.TrimSpace(op.Op))
		switch kind {
		case "add", "replace", "remove":
		default:
			return badSyntax("%q is not a PATCH operation; use add, replace or remove", op.Op)
		}
		path := attrName(op.Path)
		if kind == "remove" {
			if path == "" {
				return &Error{Status: 400, ScimType: "noTarget", Detail: "remove needs a path"}
			}
			if path == "username" {
				return &Error{Status: 400, ScimType: "mutability", Detail: "userName cannot be removed"}
			}
			if err := u.set(path, nil, true); err != nil {
				return err
			}
			continue
		}
		if len(op.Value) == 0 {
			return badValue("%s needs a value", kind)
		}
		if path != "" {
			if err := u.set(path, op.Value, false); err != nil {
				return err
			}
			continue
		}
		// No path: the value is an object of attributes, whose names may
		// carry the schema URN or a dotted sub-attribute (Entra ID sends
		// "name.givenName" this way).
		var m map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &m); err != nil {
			return badValue("%s with no path needs an object value", kind)
		}
		for _, k := range sortedKeys(m) {
			if strings.EqualFold(k, EnterpriseSchema) {
				continue
			}
			if err := u.set(attrName(k), m[k], false); err != nil {
				return err
			}
		}
	}
	return nil
}
