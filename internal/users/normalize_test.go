package users

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Passwords are compared in Unicode form NFKC, so the same password typed
// with a composed or a decomposed accent, or in full-width characters,
// matches. A hash made before from the password as typed still matches it.
func TestPasswordNormalization(t *testing.T) {
	composed := "café-Schön-2026"     // é and ö as one character each
	decomposed := "café-Schön-2026" // e and o followed by combining marks
	h, err := HashPassword(decomposed)
	if err != nil {
		t.Fatal(err)
	}
	if !ComparePassword(h, composed) || !ComparePassword(h, decomposed) {
		t.Error("the two spellings of the same password do not both match")
	}
	if ComparePassword(h, "cafe-Schon-2026") {
		t.Error("the accents were dropped")
	}
	full := "ｐａｓｓ-７３１２" // ｐａｓｓ-７３１２
	hf, err := HashPassword(full)
	if err != nil {
		t.Fatal(err)
	}
	if !ComparePassword(hf, "pass-7312") {
		t.Error("full-width characters do not match their ASCII form")
	}

	// A hash made from a password not in NFKC, before normalization.
	old, err := bcrypt.GenerateFromPassword([]byte(decomposed), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !ComparePassword(string(old), decomposed) {
		t.Error("a hash made before normalization no longer matches")
	}

	// The rules check the normalized password: full-width 12345678 is
	// the common password it looks like.
	if err := CheckNewPassword("", "１２３４５６７８"); err != ErrCommonPassword {
		t.Errorf("full-width 12345678: %v", err)
	}
}
