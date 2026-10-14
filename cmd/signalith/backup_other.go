//go:build !unix

package main

// giveToOwnerOf does nothing here: on Windows a new file takes its
// folder's access list.
func giveToOwnerOf(path, dir string) {}

func isReadOnly(err error) bool { return false }
