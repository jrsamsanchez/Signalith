package main

// makeFIFO does nothing on Windows, which has no FIFOs in folders.
func makeFIFO(path string) error { return nil }
