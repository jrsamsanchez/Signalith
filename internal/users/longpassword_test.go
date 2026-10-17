package users

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Passwords past the 72 bytes bcrypt reads are accepted whole: 64
// characters of a non-Latin script, and passwords that differ only after
// the 72nd byte are told apart. Up to 72 bytes the hash is plain bcrypt,
// so hashes made before, and by other bcrypt tools, still match.
func TestLongPasswords(t *testing.T) {
	greek := strings.Repeat("αβγδεζηθ", 8) // 64 characters, 128 bytes
	if err := CheckNewPassword("alice", greek); err != nil {
		t.Fatalf("64 Greek characters refused: %v", err)
	}
	h, err := HashPassword(greek)
	if err != nil {
		t.Fatal(err)
	}
	if !ComparePassword(h, greek) {
		t.Error("the long password does not match its hash")
	}
	if ComparePassword(h, greek[:72]) || ComparePassword(h, greek+"x") {
		t.Error("a password sharing the first 72 bytes matches")
	}
	a, b := strings.Repeat("k", 80)+"one", strings.Repeat("k", 80)+"two"
	ha, err := HashPassword(a)
	if err != nil {
		t.Fatal(err)
	}
	if ComparePassword(ha, b) {
		t.Error("passwords differing after byte 72 match")
	}

	short := strings.Repeat("q7", 36) // exactly 72 bytes
	plain, err := bcrypt.GenerateFromPassword([]byte(short), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !ComparePassword(string(plain), short) {
		t.Error("a plain bcrypt hash of a 72-byte password no longer matches")
	}
	hs, _ := HashPassword(short)
	if bcrypt.CompareHashAndPassword([]byte(hs), []byte(short)) != nil {
		t.Error("a 72-byte password is not hashed as plain bcrypt")
	}

	if _, err := HashPassword(strings.Repeat("ж", 257)); err == nil {
		t.Error("257 characters accepted")
	}
	if ComparePassword("", greek) {
		t.Error("an empty hash matches")
	}
}
