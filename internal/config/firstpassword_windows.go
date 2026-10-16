package config

// shareWithGroup does nothing on Windows: the service reads the file that
// keeps the first password itself there, so nothing is noted next to the
// config file.
func shareWithGroup(path, dir string) error { return nil }
