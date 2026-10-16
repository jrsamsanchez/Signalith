package scim

import "testing"

func FuzzParseFilter(f *testing.F) {
	for _, s := range []string{`userName eq "alice"`, `externalId eq "a\u0000b"`, `emails[type eq "work"].value eq "x"`, `id eq`, ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		flt, err := ParseFilter(s)
		if err != nil {
			return
		}
		flt.Match(&User{UserName: flt.Value, ExternalID: flt.Value, ID: flt.Value, Emails: []Email{{Value: flt.Value}}})
	})
}

func FuzzDecodeUserAndPatch(f *testing.F) {
	f.Add([]byte(`{"userName":"a","name":{"givenName":"b"},"emails":[{"value":"c","primary":true}],"active":"True"}`),
		[]byte(`{"Operations":[{"op":"Replace","path":"emails[type eq \"work\"].value","value":"x"},{"op":"replace","value":{"active":false}}]}`))
	f.Fuzz(func(t *testing.T, user, ops []byte) {
		u, err := DecodeUser(user)
		if err != nil {
			return
		}
		u.FullName()
		u.PrimaryEmail()
		o, err := DecodePatch(ops)
		if err != nil {
			return
		}
		_ = Apply(&u, o)
		u.FullName()
		u.PrimaryEmail()
	})
}
