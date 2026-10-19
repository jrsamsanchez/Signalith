// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"
)

// commonPasswordList holds commonly used passwords of at least
// MinPasswordLength characters, one per line in lower case. It comes from
// SecLists (see NOTICE).
//
//go:embed common-passwords.txt
var commonPasswordList string

// commonPasswords is commonPasswordList as a set.
var commonPasswords = sync.OnceValue(func() map[string]struct{} {
	set := make(map[string]struct{}, 2100)
	for _, line := range strings.Split(commonPasswordList, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			set[strings.ToLower(line)] = struct{}{}
		}
	}
	return set
})

// The reasons a new password is refused besides its length.
var (
	ErrCommonPassword   = errors.New("this password is on a list of commonly used passwords; choose another")
	ErrSequencePassword = errors.New("this password is a repeated or sequential run of characters (such as aaaaaaaa, 12345678 or abcdefgh); choose another")
	ErrUsernamePassword = errors.New("this password contains the username; choose another")
	ErrProductPassword  = errors.New("this password is the word signalith with only digits or symbols added; choose another")
)

// CheckNewPassword checks a password someone chooses for the user named
// username, as NIST SP 800-63B asks: long enough, not too long,
// not a commonly used password, not a repeated or sequential run of
// characters, and not the username or the product's name dressed up. It
// checks the password as HashPassword keeps it, normalized.
// username may be empty when it is not known. Passwords already set are
// never checked again: this is for new ones only.
func CheckNewPassword(username, pw string) error {
	pw = NormalizePassword(pw)
	if err := checkLength(pw); err != nil {
		return err
	}
	lower := strings.ToLower(pw)
	if _, ok := commonPasswords()[lower]; ok {
		return ErrCommonPassword
	}
	if isRun(lower) {
		return ErrSequencePassword
	}
	if name := NormalizeUsername(username); len([]rune(name)) >= 3 && strings.Contains(lower, name) {
		return ErrUsernamePassword
	}
	if strings.TrimFunc(lower, func(r rune) bool { return !unicode.IsLetter(r) }) == "signalith" {
		return ErrProductPassword
	}
	return nil
}

// MaxPasswordLength is the longest password Signalith accepts, in
// characters: well past the 64 NIST SP 800-63B asks for, in any script.
const MaxPasswordLength = 256

// checkLength refuses a password that is too short or too long.
func checkLength(pw string) error {
	n := len([]rune(pw))
	if n < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if n > MaxPasswordLength {
		return fmt.Errorf("password must be at most %d characters", MaxPasswordLength)
	}
	return nil
}

// isRun reports whether pw is one character repeated ("aaaaaaaa"), a short
// group of up to four characters repeated ("abcabcabc"), or a run of
// characters that each come one after the other, up or down ("12345678",
// "abcdefgh", "87654321").
func isRun(pw string) bool {
	r := []rune(pw)
	for unit := 1; unit <= 4 && unit < len(r); unit++ {
		if len(r)%unit != 0 {
			continue
		}
		repeated := true
		for i := unit; i < len(r); i++ {
			if r[i] != r[i-unit] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	for _, step := range []rune{1, -1} {
		sequential := true
		for i := 1; i < len(r); i++ {
			if r[i]-r[i-1] != step {
				sequential = false
				break
			}
		}
		if sequential {
			return true
		}
	}
	return false
}
