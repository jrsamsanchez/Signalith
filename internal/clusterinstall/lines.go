// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterinstall

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Line is what the pasted lines are made from.
type Line struct {
	// URL is the address the token names (https://siem-a:9000): the new
	// server downloads the script and the program from it.
	URL string
	// Token is the join token, SJ1.….
	Token string
	// Version is the issuer's version; a new server must run the same.
	Version string
	// GOOS and GOARCH are the issuer's kind of machine, and BinarySHA256
	// its program's SHA-256: a new server of the same kind downloads that
	// program. An empty BinarySHA256 downloads nothing.
	GOOS, GOARCH string
	BinarySHA256 string
}

// Commands are the lines the Add a server dialog shows, one per kind of
// new server, and a note for each when it needs something first.
type Commands struct {
	Linux       string `json:"linux"`
	LinuxNote   string `json:"linux_note,omitempty"`
	Windows     string `json:"windows"`
	WindowsNote string `json:"windows_note,omitempty"`
	// Docker is the .env file for deploy/docker/docker-compose.server.yml,
	// and DockerRun the command that starts it.
	Docker    string `json:"docker"`
	DockerRun string `json:"docker_run"`
}

var (
	tokenText   = regexp.MustCompile(`^SJ1\.[A-Za-z0-9_-]+$`)
	versionText = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,64}$`)
	releaseText = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
	hexText     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Released reports whether v is a released version, one with packages,
// an image and downloads on GitHub (not a development build).
func Released(v string) bool { return releaseText.MatchString(v) }

// checkURL refuses a server address that is not https://host:port, or
// that holds anything that would need quoting in a shell or PowerShell,
// since it is pasted into one.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the server's address must be https://host:port")
	}
	if strings.ContainsAny(raw, "'\"` $;&|<>\\") {
		return errors.New("the server's address has characters a pasted line cannot carry")
	}
	return nil
}

// check refuses anything that would need quoting in a shell or
// PowerShell, since it is pasted into one.
func (l Line) check() error {
	if err := checkURL(l.URL); err != nil {
		return err
	}
	if !tokenText.MatchString(l.Token) {
		return errors.New("not a join token")
	}
	if !versionText.MatchString(l.Version) {
		return errors.New("not a version")
	}
	if l.BinarySHA256 != "" && !hexText.MatchString(l.BinarySHA256) {
		return errors.New("not a SHA-256")
	}
	return nil
}

// Lines makes the pasted lines.
//
// Linux: the line downloads install.sh, checks its SHA-256 and runs it
// with sudo, giving it the token on its standard input. The script downloads the issuer's program when the issuer
// runs Linux on the same processor, and checks it too.
//
// Windows (an elevated PowerShell, Windows PowerShell 5.1 or PowerShell
// 7): the same with install.ps1.
//
// Docker: an .env file next to deploy/docker/docker-compose.server.yml.
//
// The script download does not check the server's certificate, which a
// new machine does not trust yet: the SHA-256 in the line checks the
// script, the script checks the program, and "signalith join" trusts only
// the certificate authority the token names.
func Lines(l Line) (Commands, error) {
	if err := l.check(); err != nil {
		return Commands{}, err
	}
	base := strings.TrimSuffix(l.URL, "/")
	sha := ScriptSHA256()
	var c Commands

	// The token reaches the script on its standard input (echo is built
	// into the shell), so it is never on a command line in the process
	// list.
	linux := fmt.Sprintf("f=$(mktemp) && curl -fsSk --proto '=https' %s/api/cluster/join/install.sh -o \"$f\" && echo \"%s  $f\" | sha256sum -c --quiet && echo '%s' | sudo sh \"$f\" --from %s --version %s",
		base, sha.SH, l.Token, base, l.Version)
	if l.GOOS == "linux" && l.BinarySHA256 != "" {
		linux += " --sha256 " + l.BinarySHA256
	} else {
		c.LinuxNote = fmt.Sprintf("This server runs %s, so it cannot hand out the Linux program: install the Signalith %s package on the new server first (%s), then run the line.", platformName(l.GOOS), l.Version, docsInstall)
	}
	c.Linux = linux + " --join -"

	// $ProgressPreference: Windows PowerShell 5.1 downloads many times
	// slower while it draws a progress bar.
	ps := fmt.Sprintf("$u='%s'; $f=Join-Path $env:TEMP 'signalith-join.ps1'; $ProgressPreference='SilentlyContinue'; "+
		"if ($PSVersionTable.PSVersion.Major -ge 6) { Invoke-WebRequest \"$u/api/cluster/join/install.ps1\" -OutFile $f -SkipCertificateCheck } "+
		"else { "+ps51Get+"[SignalithGet]::Save(\"$u/api/cluster/join/install.ps1\", $f) }; "+
		"if ((Get-FileHash $f -Algorithm SHA256).Hash -ne '%s') { throw 'The downloaded script is not the one this line names, so it was not run.' }; "+
		"Set-ExecutionPolicy -Scope Process Bypass -Force; & $f -From $u -Version %s",
		base, strings.ToUpper(sha.PS1), l.Version)
	if l.GOOS == "windows" && l.BinarySHA256 != "" {
		ps += " -Sha256 " + l.BinarySHA256
	} else {
		c.WindowsNote = fmt.Sprintf("This server runs %s, so it cannot hand out the Windows program: install the Signalith %s .msi on the new server first (%s), then run the line.", platformName(l.GOOS), l.Version, docsInstall)
	}
	c.Windows = ps + " -Join '" + l.Token + "'"

	image := "main"
	if Released(l.Version) {
		image = l.Version
	}
	c.Docker = strings.Join([]string{
		"# Signalith " + l.Version + ": join the cluster at " + base,
		"SIGNALITH_JOIN=" + l.Token,
		"SIGNALITH_VERSION=" + image,
		"# This server's name on the Servers page.",
		"SIGNALITH_NODE_NAME=signalith-2",
		"# The address the other servers reach this one at.",
		"SIGNALITH_NODE_URL=https://<this computer's address>:9000",
		"",
	}, "\n")
	c.DockerRun = "docker compose -f deploy/docker/docker-compose.server.yml --env-file deploy/docker/join.env up -d"
	return c, nil
}

const docsInstall = "https://signalith.io/docs/install-packages/"

func platformName(goos string) string {
	switch goos {
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	case "":
		return "another system"
	}
	return goos
}

// signalithGetCS is Windows PowerShell 5.1's download for the pasted
// lines and the install scripts, in C#: it saves one https address to a
// file without checking the certificate (the line checks the file's
// SHA-256 instead), follows no redirect and takes only a 200. A script
// block as the certificate check does not work there: Invoke-WebRequest
// checks the certificate on a thread with no PowerShell to run it ("There
// is no Runspace available"), and the download fails with "An unexpected
// error occurred on a send". The check is also only for this one request,
// not for the whole PowerShell.
const signalithGetCS = `public static class SignalithGet { static bool Any(object s, System.Security.Cryptography.X509Certificates.X509Certificate c, System.Security.Cryptography.X509Certificates.X509Chain h, System.Net.Security.SslPolicyErrors e) { return true; } public static void Save(string url, string file) { var r = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url); r.AllowAutoRedirect = false; r.ServerCertificateValidationCallback = Any; using (var p = (System.Net.HttpWebResponse)r.GetResponse()) { if ((int)p.StatusCode != 200) { throw new System.Net.WebException("the server answered " + (int)p.StatusCode); } using (var s = p.GetResponseStream()) using (var o = System.IO.File.Create(file)) { s.CopyTo(o); } } } }`

// ps51Get defines SignalithGet once in this PowerShell and turns TLS 1.2
// on; the line then calls [SignalithGet]::Save(url, $f).
const ps51Get = "if (-not ('SignalithGet' -as [type])) { Add-Type -TypeDefinition '" + signalithGetCS + "' }; " +
	"[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; "
