//go:build !unix

package content

// giveToFolderOwner does nothing where files inherit their folder's
// permissions.
func giveToFolderOwner(path, dir string) error { return nil }
