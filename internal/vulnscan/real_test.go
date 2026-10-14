package vulnscan

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestRealNmap scans this machine with the Nmap installed here, when
// there is one; CI runners without Nmap skip it.
func TestRealNmap(t *testing.T) {
	path := FindNmap()
	if path == "" || testing.Short() {
		t.Skip("Nmap is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	v, err := NmapVersion(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Nmap %s at %s", v, path)
	if err := selfTest(ctx, path); err != nil {
		t.Fatal(err)
	}
	port := os.Getenv("SIGNALITH_TEST_PORT")
	if port == "" {
		return
	}
	var last Progress
	hosts, err := (&Runner{Path: path}).Scan(ctx, Target{Networks: []string{"127.0.0.1"}, Ports: port}, func(p Progress) { last = p })
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("hosts %+v, progress %+v", hosts, last)
	if len(hosts) != 1 || len(hosts[0].Services) != 1 {
		t.Fatalf("hosts = %+v", hosts)
	}
}
