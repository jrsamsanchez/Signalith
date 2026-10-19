//go:build !windows

package main

import "errors"

func newLocalOpenSearch() (localOpenSearch, error) {
	return nil, errors.New("the opensearch command is for Windows, where the installer runs it; on Linux install OpenSearch from its own packages (docs/install-packages.md)")
}
