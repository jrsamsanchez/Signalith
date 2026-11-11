// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build race

package search

// raceOn says the race detector is on: sync.Pool then drops what it is
// given, so the regexp package allocates a new matcher for every call
// and a count of bytes allocated says nothing about the search.
const raceOn = true
