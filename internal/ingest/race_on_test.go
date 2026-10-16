//go:build race

package ingest

// raceEnabled is true when the tests run with -race, which makes code
// several times slower, so timing checks allow more time.
const raceEnabled = true
