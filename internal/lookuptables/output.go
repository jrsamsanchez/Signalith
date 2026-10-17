package lookuptables

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"slices"
)

// OutputMode says what Output does with a table that already exists.
type OutputMode int

const (
	// OutputCreate only makes a new table: one that exists is ErrExists.
	OutputCreate OutputMode = iota
	// OutputAppend adds the rows after the table's own.
	OutputAppend
	// OutputReplace replaces the table's rows and columns.
	OutputReplace
)

// ErrExists is Output's OutputCreate on a table that exists.
var ErrExists = errors.New("the lookup table exists")

// errTooBig is a table Output would write past MaxTableBytes.
var errTooBig = parseErr("the table would be over %d MB, the most a lookup table can be", MaxTableBytes>>20)

// Output writes rows of columns to table name, as a search's outputlookup
// does, through the same checks as an upload (PutWithOptions). A table
// that exists keeps how its keys match; appended rows bring their new
// columns after the table's own.
func (s *Store) Output(name string, columns []string, rows [][]string, mode OutputMode) (*Table, error) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	if !ValidName(name) {
		return nil, fmt.Errorf("%q cannot name a lookup table; use lower-case letters, digits, - and _ (up to 64)", name)
	}
	old, exists := s.Get(name)
	var opts Options
	if exists {
		if mode == OutputCreate {
			return nil, ErrExists
		}
		opts = old.Options
	}
	if exists && mode == OutputAppend {
		cols := slices.Clone(old.Columns)
		var at []int
		for _, c := range columns {
			i := slices.Index(cols, c)
			if i < 0 {
				i = len(cols)
				cols = append(cols, c)
			}
			at = append(at, i)
		}
		if len(cols) > MaxColumns {
			return nil, parseErr("the table would have %d columns; a lookup table can have up to %d", len(cols), MaxColumns)
		}
		var all [][]string
		all = append(all, old.Rows...)
		for _, r := range rows {
			row := make([]string, len(cols))
			for j, v := range r {
				row[at[j]] = v
			}
			all = append(all, row)
		}
		columns, rows = cols, all
	}
	data, err := encodeCSV(columns, rows)
	if err != nil {
		return nil, err
	}
	return s.PutWithOptions(name, data, opts)
}

// encodeCSV writes a header and rows as they are, stopping once they pass
// MaxTableBytes.
func encodeCSV(columns []string, rows [][]string) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write(columns); err != nil {
		return nil, err
	}
	for _, r := range rows {
		if err := w.Write(r); err != nil {
			return nil, err
		}
		w.Flush()
		if b.Len() > MaxTableBytes {
			return nil, errTooBig
		}
	}
	w.Flush()
	if b.Len() > MaxTableBytes {
		return nil, errTooBig
	}
	return b.Bytes(), w.Error()
}
