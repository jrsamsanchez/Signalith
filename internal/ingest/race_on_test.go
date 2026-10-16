//go:build race

package ingest

// raceBuild is set when the tests run with the race detector, which
// makes code several times slower: time limits allow for it.
const raceBuild = true
