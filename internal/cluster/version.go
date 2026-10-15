package cluster

import (
	"slices"
	"strconv"
	"strings"
)

// NewerVersion reports whether version a, which reads stored formats up to
// levelA, is newer than b, which reads up to levelB: the one that reads
// higher levels, else the higher release number, else the build after a
// release (one with a suffix, such as 0.2.0-next+abc). A version without
// numbers (dev) or one that cannot be read is never newer than another at
// the same level, so test builds never hand the jobs to each other.
func NewerVersion(a, b string, levelA, levelB int) bool {
	if levelA != levelB {
		return levelA > levelB
	}
	na, sa := splitVersion(a)
	nb, sb := splitVersion(b)
	if len(na) == 0 {
		return false
	}
	if c := slices.Compare(na, nb); c != 0 {
		return c > 0
	}
	return sa != "" && sb == ""
}

// splitVersion splits 0.2.0-next+abc into [0 2 0] and -next+abc; dev has
// no numbers and the suffix dev.
func splitVersion(v string) ([]int, string) {
	v = strings.TrimPrefix(v, "v")
	var nums []int
	for len(v) > 0 {
		i := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
		if i < 0 {
			i = len(v)
		}
		if i == 0 {
			break
		}
		n, _ := strconv.Atoi(v[:i])
		nums = append(nums, n)
		v = v[i:]
		if !strings.HasPrefix(v, ".") {
			break
		}
		v = v[1:]
	}
	return nums, v
}
