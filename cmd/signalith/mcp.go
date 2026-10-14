package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/mcp"
)

const mcpUsage = `usage: signalith mcp [-url URL] [-user name] [-password-file file] [-ca file] [-check]

Runs a read-only MCP (Model Context Protocol) server on standard input and
output, for AI tools such as Claude Desktop. It reads from a Signalith server
as a Signalith user, so that user's role decides what it can see, and it has
no tool that changes anything. See docs/ai-tools.md.

Settings, as flags or environment variables:
  -url            SIGNALITH_URL            the server's web address, such as https://siem.example.com:8080
  -user           SIGNALITH_USER           the Signalith user to read as (a viewer or analyst account is best)
                  SIGNALITH_PASSWORD       that user's password
  -password-file  SIGNALITH_PASSWORD_FILE  or a file holding the password
  -ca             SIGNALITH_CA_FILE        a PEM file of the CA to trust, when the system does not trust the server's certificate
  -check          check the settings, print the user and exit
`

func cmdMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, mcpUsage) }
	addr := fs.String("url", os.Getenv("SIGNALITH_URL"), "")
	user := fs.String("user", os.Getenv("SIGNALITH_USER"), "")
	passFile := fs.String("password-file", os.Getenv("SIGNALITH_PASSWORD_FILE"), "")
	caFile := fs.String("ca", os.Getenv("SIGNALITH_CA_FILE"), "")
	check := fs.Bool("check", false, "")
	fs.Parse(args)

	pass := os.Getenv("SIGNALITH_PASSWORD")
	if *passFile != "" {
		b, err := os.ReadFile(*passFile)
		if err != nil {
			return fmt.Errorf("reading the password file: %w", err)
		}
		pass = strings.TrimRight(string(b), "\r\n")
	}
	c, err := newMCPClient(*addr, *user, pass, *caFile)
	if err != nil {
		return err
	}
	srv := mcp.NewServer(c, version)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *check {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		for _, t := range srv.Tools {
			if t.Name != "whoami" {
				continue
			}
			res, err := t.Call(ctx, json.RawMessage("{}"))
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(res, "", "  ")
			fmt.Printf("Signalith answered; the MCP server will read as:\n%s\n", b)
			return nil
		}
	}
	// Standard output carries the protocol, so the log goes to standard
	// error, which AI tools keep in their own logs.
	srv.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv.Log.Info("signalith MCP server started", "server", c.BaseURL.Redacted(), "user", c.User, "version", version)
	return srv.Serve(ctx, os.Stdin, os.Stdout)
}

// newMCPClient checks the settings of signalith mcp and returns the client
// it reads through.
func newMCPClient(addr, user, pass, caFile string) (*mcp.Client, error) {
	if addr == "" {
		return nil, errors.New("set the Signalith server's address with -url or SIGNALITH_URL")
	}
	if !strings.Contains(addr, "://") {
		addr = "https://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("the Signalith address %q is not a web address such as https://siem.example.com:8080", addr)
	}
	if u.User != nil {
		return nil, errors.New("put the username and password in SIGNALITH_USER and SIGNALITH_PASSWORD, not in the address")
	}
	u.Path, u.RawQuery, u.Fragment = strings.TrimRight(u.Path, "/"), "", ""
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("%s uses plain http, which would send the password unencrypted; use https", u.Redacted())
	}
	if user == "" || pass == "" {
		return nil, errors.New("set the Signalith user with -user or SIGNALITH_USER, and its password with SIGNALITH_PASSWORD or SIGNALITH_PASSWORD_FILE")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading the CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificate", caFile)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &mcp.Client{
		BaseURL: u, User: user, Password: pass,
		// A search may run for up to two minutes on the server.
		HTTP:      &http.Client{Transport: tr, Timeout: 3 * time.Minute},
		UserAgent: "signalith-mcp/" + version,
	}, nil
}

func loopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
