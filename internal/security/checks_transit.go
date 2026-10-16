package security

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// prefixText shows a range as people write it: a single address without
// its /32 or /128.
func prefixText(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func prefixList(list []netip.Prefix) []string {
	out := make([]string, len(list))
	for i, p := range list {
		out[i] = prefixText(p)
	}
	return out
}

// checkHTTPS: transit.https.
func checkHTTPS(f *Facts) *Check {
	c := f.Config
	switch c.Server.TLSMode() {
	case config.TLSAuto:
		return &Check{State: Good, Line: "The web page, the API and agents use HTTPS, with Signalith's own certificate."}
	case config.TLSFiles:
		return &Check{State: Good, Line: "The web page, the API and agents use HTTPS, with your own certificate."}
	}
	host, port := listenHost(c.Server.Listen)
	if port == "" {
		port = c.Server.Listen
	}
	if host != "" && isLoopback(host) {
		return &Check{State: Good, Line: "HTTPS is off, but Signalith only answers on this computer (" + c.Server.Listen + "), so nothing it sends crosses the network."}
	}
	// What reached Signalith over plain HTTP, not through the proxy, in
	// the last day: sign-ins and agents.
	var direct []string
	var signIns, agents []string
	if f.Runtime != nil {
		signIns, agents = f.Runtime.DirectPlain, f.Runtime.DirectPlainAgents
		if n := len(signIns); n > 0 {
			direct = append(direct, itoa(n)+plural(n, " computer", " computers")+" signed in to Signalith directly over plain HTTP in the last day: "+shorten(signIns, 5)+".")
		}
		if n := len(agents); n > 0 {
			direct = append(direct, itoa(n)+plural(n, " agent", " agents")+" sent events to Signalith directly over plain HTTP in the last day: "+shorten(agents, 5)+".")
		}
	}
	directFix := func() *Fix {
		var steps []string
		if len(signIns) > 0 {
			steps = append(steps, "Tell people to use the proxy's https:// address.")
		}
		if len(agents) > 0 {
			steps = append(steps, "Give those agents a new configuration from Add data, with Public address set to the proxy's https:// address.")
		}
		steps = append(steps, "Set Listen address so only the proxy can reach Signalith, such as 127.0.0.1:"+port+" when the proxy runs on this computer.")
		return &Fix{Steps: steps, Setting: "server.listen", Docs: doc(docHTTPSProxy)}
	}
	if c.Server.LegacyProxied() {
		where := "a reverse proxy"
		if f.Runtime != nil && len(f.Runtime.LegacyProxies) > 0 {
			where = "the reverse proxy at " + shorten(f.Runtime.LegacyProxies, 3)
		}
		return &Check{State: Attention, Line: "HTTPS is left to " + where + ", which Signalith trusts only because signalith.yaml was written before HTTPS was the default.",
			Details: direct, Fix: &Fix{
				Steps: []string{
					"List the proxy's address under Trusted reverse proxies.",
					"If no reverse proxy serves HTTPS for Signalith, turn HTTPS on with Automatic instead.",
				},
				Setting: "server.trusted_proxies", Docs: doc(docHTTPSProxy)}}
	}
	if proxies := c.Server.TrustedProxyList(); len(proxies) > 0 {
		if len(direct) > 0 {
			return &Check{State: Attention, Line: "A reverse proxy serves HTTPS, but " + direct[0], Details: direct[1:], Fix: directFix()}
		}
		return &Check{State: Good, Line: "A reverse proxy at " + shorten(prefixList(proxies), 3) + " serves HTTPS for Signalith.",
			Tip: &Fix{Steps: []string{"Signalith also answers plain HTTP from any computer that can reach port " + port +
				". If a firewall doesn't already limit that port to the proxy, set Listen address to 127.0.0.1:" + port +
				" (when the proxy runs on this computer), or turn on HTTPS between the proxy and Signalith."},
				Setting: "server.listen", Docs: doc(docHTTPSProxy)}}
	}
	return &Check{State: Risk, Line: "HTTPS is off, so passwords, sessions and events cross the network unencrypted.", Fix: &Fix{
		Steps: []string{
			"Turn HTTPS on with Automatic, and restart when the Settings page asks.",
			"Give each agent a new configuration from Add data. Until then, Agents on plain HTTP can accept them for now.",
			"If a reverse proxy in front already serves HTTPS, list it under Trusted reverse proxies instead.",
		},
		Setting: "server.tls.mode", Docs: doc(docHTTPSUpgrade)}}
}

// problem is one of several things a check found, worst first; the
// first is the check's line and fix, the others go in its details.
type problem struct {
	state State
	line  string
	fix   *Fix
}

// worst builds a check from the problems found, or returns nil when
// there are none.
func worst(probs []problem) *Check {
	if len(probs) == 0 {
		return nil
	}
	slices.SortStableFunc(probs, func(a, b problem) int { return a.state.order() - b.state.order() })
	c := &Check{State: probs[0].state, Line: probs[0].line, Fix: probs[0].fix}
	for _, p := range probs[1:] {
		c.Details = append(c.Details, p.line)
	}
	return c
}

// daysLeft counts the whole days from now to t.
func daysLeft(now, t time.Time) int { return int(t.Sub(now) / (24 * time.Hour)) }

func inDays(n int) string {
	if n < 1 {
		return "in less than a day"
	}
	return "in " + itoa(n) + plural(n, " day", " days")
}

// checkCertificate: transit.certificate.
func checkCertificate(f *Facts) *Check {
	t := f.TLS
	if t == nil {
		return nil
	}
	if t.Leaf == nil {
		return &Check{State: Unknown, Line: "Signalith couldn't read the certificate it serves.",
			Fix: &Fix{Steps: []string{"The server log says why when Signalith starts."}}}
	}
	auto := t.Mode == config.TLSAuto
	leaf := t.Leaf
	left := daysLeft(f.Now, leaf.NotAfter)
	restart := &Fix{Steps: []string{"Restart Signalith; it tries to renew when it starts. If that fails, the log says why."},
		Commands: restartCommands()}
	var replace *Fix
	if !auto {
		replace = &Fix{Steps: []string{"Put the new certificate and key in " + t.CertFile + " and " + t.KeyFile + ". Signalith loads them by itself."},
			Commands: ownOnly(f, cmds("openssl x509 -in "+sh(t.CertFile)+" -noout -enddate", "", "")),
			Docs:     doc(docHTTPSOwn)}
	}
	var probs []problem
	switch {
	case !f.Now.Before(leaf.NotAfter):
		fix := restart
		if !auto {
			fix = replace
		}
		probs = append(probs, problem{Risk, "The certificate expired on " + day(leaf.NotAfter) +
			". Agents hold their events until it's replaced, and browsers warn on every visit.", fix})
	case !auto && left <= 30:
		probs = append(probs, problem{Attention, "Your certificate expires on " + day(leaf.NotAfter) + ", " + inDays(left) +
			". Replace the files before then; Signalith loads the new ones by itself.", replace})
	case auto && left <= 21:
		probs = append(probs, problem{Attention, "Signalith's certificate expires on " + day(leaf.NotAfter) +
			" and hasn't renewed itself. The server log says why.", restart})
	}
	if auto && len(t.Outside) > 0 {
		// They are already among the names it should cover (Outside
		// lists only those), so only a new certificate authority is
		// needed.
		fix := &Fix{Steps: []string{"Make a new certificate authority that includes them, and switch to it. The one in use keeps working meanwhile."},
			Action: "ca.prepare", Docs: doc(docHTTPSNames)}
		if t.ClusterCA {
			fix = clusterCAFix("Until then, have people and agents use a name the certificate covers.", docHTTPSNames)
		}
		probs = append(probs, problem{Attention, "The certificate leaves out " + shorten(t.Outside, 5) +
			", which people or agents may use to reach this server.", fix})
	}
	if !auto && t.PublicHost != "" && !t.CoversPublicHost {
		probs = append(probs, problem{Attention, "Your certificate doesn't cover " + t.PublicHost + ", the address agents are set up with.", &Fix{
			Steps:   []string{"Use a certificate that covers " + t.PublicHost + ", or set Public address to a name the certificate covers."},
			Setting: "server.public_url", Docs: doc(docHTTPSOwn)}})
	}
	if !auto && t.CAMissing {
		probs = append(probs, problem{Attention, "Your certificate file doesn't include the authority that issued it, so Add data can't give it to agents.", &Fix{
			Steps: []string{"Add the certificate of the authority that issued yours after it, in the certificate file."},
			Docs:  doc(docHTTPSOwn)}})
	}
	if !auto && leaf.NoName {
		// Agents set up with an IP address check the certificate against
		// a host name it carries, since its CA vouches for others too.
		probs = append(probs, problem{Attention, "Your certificate covers only IP addresses, so agents can't check it belongs to this server, and Add data can't set them up.", &Fix{
			Steps: []string{"Get a certificate that also includes this server's host name. Agents can keep using its IP address."},
			Docs:  doc(docHTTPSOwn)}})
	}
	if !auto && (leaf.RSABits > 0 && leaf.RSABits < 2048 || leaf.SHA1) {
		var weak []string
		if leaf.RSABits > 0 && leaf.RSABits < 2048 {
			weak = append(weak, "a "+itoa(leaf.RSABits)+"-bit RSA key")
		}
		if leaf.SHA1 {
			weak = append(weak, "SHA-1")
		}
		probs = append(probs, problem{Attention, "Your certificate uses " + joinAnd(weak) + ", which is too weak to trust today.", replace})
	}
	if auto && t.CA != nil && daysLeft(f.Now, t.CA.NotAfter) <= 180 {
		if t.ClusterCA {
			probs = append(probs, problem{Attention, "The certificate authority all servers share expires on " + day(t.CA.NotAfter) + ".",
				clusterCAFix("", docHTTPSSwitch)})
		} else {
			probs = append(probs, problem{Attention, "Signalith's certificate authority expires on " + day(t.CA.NotAfter) +
				". Make a new one and switch to it before then.", &Fix{
				Steps:  []string{"Make a new certificate authority. The one in use keeps working meanwhile.", "Give it to browsers and agents, then switch."},
				Action: "ca.prepare", Docs: doc(docHTTPSSwitch)}})
		}
	}
	if c := worst(probs); c != nil {
		return c
	}
	if auto {
		return &Check{State: Good, Line: "Signalith's own certificate is valid until " + day(leaf.NotAfter) + " and renews itself 30 days before."}
	}
	if t.PublicHost != "" {
		return &Check{State: Good, Line: "Your certificate is valid until " + day(leaf.NotAfter) + " and covers " + t.PublicHost + "."}
	}
	return &Check{State: Good, Line: "Your certificate is valid until " + day(leaf.NotAfter) + "."}
}

// checkCAScope: transit.ca_scope.
func checkCAScope(f *Facts) *Check {
	t := f.TLS
	if t == nil || t.Mode != config.TLSAuto || t.CA == nil {
		return nil
	}
	var c *Check
	prepare := &Fix{Steps: []string{"Make a new certificate authority. The one in use keeps working meanwhile.", "Give it to browsers and agents, then switch."},
		Action: "ca.prepare", Docs: doc(docHTTPSSwitch)}
	panel := &Fix{Steps: []string{"Continue under Switching certificate authority, at the top of the Security page."},
		Action: "ca.panel", Docs: doc(docHTTPSSwitch)}
	if t.ClusterCA {
		prepare = clusterCAFix("", docHTTPSSwitch)
	}
	setting := t.ScopeSetup
	if setting == "" {
		setting = tlsauto.ScopeStandard
	}
	switch {
	case t.Next != nil:
		c = &Check{State: Attention, Line: "A new certificate authority is ready. Switch to it once browsers and agents trust it.", Fix: panel}
	case t.Previous != nil:
		since := "recently"
		if !t.Previous.At.IsZero() {
			since = ago(f.Now, t.Previous.At)
		}
		c = &Check{State: Attention, Line: "Signalith switched to a new certificate authority " + since +
			". Remove the old one once nothing refuses the new certificate.", Fix: panel}
		if n := len(t.Refusals); n > 0 {
			var addrs []string
			for _, r := range t.Refusals {
				if !slices.Contains(addrs, r.Address) {
					addrs = append(addrs, r.Address)
				}
			}
			n = len(addrs)
			c.Details = append(c.Details, itoa(n)+plural(n, " computer", " computers")+" refused the new certificate since the switch: "+shorten(addrs, 5)+".")
		}
	case t.CA.Scope == tlsauto.ScopeUnconstrained:
		c = &Check{State: Attention, Line: "Signalith's certificate authority was made by an older version and can vouch for any website, to every computer that trusts it.", Fix: prepare}
	case t.CA.AnyUse:
		c = &Check{State: Attention, Line: "Signalith's certificate authority was made by an older version and isn't limited to websites. " +
			"If its key were stolen, it could sign programs or email that computers trusting it would accept.", Fix: prepare}
	case t.CA.Scope != setting && t.ClusterCA:
		c = &Check{State: Attention, Line: "You chose a " + setting + " certificate authority, but the one all servers share is " + t.CA.Scope + ".", Fix: prepare}
	case t.CA.Scope != setting:
		c = &Check{State: Attention, Line: "You chose a " + setting + " certificate authority, but the one in use is " + t.CA.Scope +
			". Make the new one and switch when you're ready.", Fix: prepare}
	case t.CA.Scope == tlsauto.ScopeStrict:
		c = &Check{State: Good, Line: "Signalith's certificate authority can vouch only for this server's own names and addresses.", Tip: scopeTip(f, tlsauto.ScopeStrict)}
	default:
		c = &Check{State: Good, Line: "Signalith's certificate authority can vouch only for this server and for private network names, never for public websites.", Tip: scopeTip(f, tlsauto.ScopeStandard)}
	}
	if c.State == Good && len(t.CA.Subtrees) > 0 {
		// Made by an earlier version: its names cover the names under
		// them too. Honest about it, without an alarm.
		ends := make([]string, len(t.CA.Subtrees))
		for i, n := range t.CA.Subtrees {
			ends[i] = "." + n
		}
		if t.CA.Scope == tlsauto.ScopeStrict {
			c.Line = "Signalith's certificate authority can vouch only for this server's own names and addresses, and for names that end in " + orList(ends, 3) + "."
		} else {
			c.Line = "Signalith's certificate authority can vouch only for this server, private network names, and names that end in " + orList(ends, 3) + "."
		}
		c.Details = append(c.Details, "It was made by an earlier version. A new one covers each of this server's names exactly.")
	}
	switch {
	case t.ClusterCA:
		c.Details = append(c.Details, "All the cluster's servers share this certificate authority, and its key is kept sealed in the shared settings, not on this server's disk.")
	case f.Runtime != nil && f.Runtime.ClusterServer != "":
		c.Details = append(c.Details, "Each server has its own certificate authority. This is "+f.Runtime.ClusterServer+"'s.")
	}
	return c
}

// clusterCAFix is the fix of a problem with the certificate authority all
// the cluster's servers share, which cannot be changed yet: then, if
// given, what to do meanwhile.
func clusterCAFix(then string, docs DocLink) *Fix {
	steps := []string{"This server uses the certificate authority all the cluster's servers share. It can't be changed yet; that comes in a later version."}
	if then != "" {
		steps = append(steps, then)
	}
	return &Fix{Steps: steps, Docs: doc(docs)}
}

// scopeTip explains standard and strict, the one place the page does.
func scopeTip(f *Facts, inUse string) *Fix {
	mark := func(s string) string {
		if s == inUse {
			return " (in use)"
		}
		return ""
	}
	names := "this server's own names and addresses"
	if l := f.TLS.WouldCover[tlsauto.ScopeStrict]; len(l) > 0 {
		names = shorten(ownNamesFirst(l), 3)
	}
	if f.TLS.ClusterCA {
		return &Fix{Label: "Standard or strict?", Steps: []string{
			"Computers that trust Signalith's certificate authority accept any certificate it makes. Both choices keep it from ever vouching for public websites.",
			"Standard" + mark(tlsauto.ScopeStandard) + ". It can also vouch for private network names and addresses, such as intranet.corp or 192.168.1.5. " +
				"If someone stole its key, they could pose as other private sites to computers that trust it. In a cluster the key is kept sealed with the cluster key, not on a server's disk.",
			"Strict" + mark(tlsauto.ScopeStrict) + ". It can vouch only for the names it was made with.",
			"All the cluster's servers share this certificate authority. Changing it comes in a later version.",
		}, Docs: doc(docHTTPSReach)}
	}
	return &Fix{Label: "Standard or strict?", Steps: []string{
		"Computers that trust Signalith's certificate authority accept any certificate it makes. Both choices keep it from ever vouching for public websites.",
		"Standard" + mark(tlsauto.ScopeStandard) + ". It can also vouch for private network names and addresses, such as intranet.corp or 192.168.1.5. " +
			"A new address for this server works right away. If someone stole its key from this server, they could pose as other private sites to computers that trust it.",
		"Strict" + mark(tlsauto.ScopeStrict) + ". It can vouch only for " + names + ". A stolen key is no more use than this server's own certificate. " +
			"But a new name or address later means a new certificate authority, which every browser and agent must trust again.",
		"Strict suits a server whose name and address won't change, especially when many computers trust it.",
	}, Action: "ca.prepare", Docs: doc(docHTTPSReach)}
}

// ownNamesFirst puts localhost and the loopback addresses, which every
// certificate authority covers, after this server's own names.
func ownNamesFirst(names []string) []string {
	out := append([]string(nil), names...)
	loop := func(n string) bool {
		if strings.EqualFold(n, "localhost") {
			return true
		}
		a, err := netip.ParseAddr(n)
		return err == nil && a.IsLoopback()
	}
	slices.SortStableFunc(out, func(a, b string) int {
		switch la, lb := loop(a), loop(b); {
		case !la && lb:
			return -1
		case la && !lb:
			return 1
		}
		return 0
	})
	return out
}

// checkAgentsPlain: transit.agents_plain.
func checkAgentsPlain(f *Facts) *Check {
	c := f.Config
	if !c.Server.HTTPS() {
		return nil
	}
	if !c.Server.PlaintextIngest() {
		return &Check{State: Good, Line: "Agents can only send events over HTTPS."}
	}
	fix := &Fix{Steps: []string{"Choose Refuse them under Agents on plain HTTP. An agent that was missed keeps its events, and the Health page names it."},
		Setting: "server.tls.plaintext_ingest", Page: &PageLink{ID: "data", Label: "Open Add data"}, Docs: doc(docHTTPSUpgrade)}
	// Agents on this computer: what they send never crosses the network.
	var local []string
	if !f.CLI() {
		switch n := f.Runtime.LocalPlainSenders; {
		case n == 1:
			local = []string{"An agent on this computer still sends over plain HTTP. Its events don't cross the network."}
		case n > 1:
			local = []string{itoa(n) + " agents on this computer still send over plain HTTP. Their events don't cross the network."}
		}
	}
	switch {
	case f.CLI():
		return &Check{State: Attention, Line: "Agents on plain HTTP are still accepted. The Security page shows whether any still send that way.", Fix: fix}
	case f.Runtime.PlainSenderCount > 0:
		n := f.Runtime.PlainSenderCount
		fix.Steps = []string{"Give each agent listed a new configuration from Add data.", "Then choose Refuse them under Agents on plain HTTP."}
		line := itoa(n) + plural(n, " agent sends", " agents send") + " events over plain HTTP, which anyone on the network can read: " +
			shorten(f.Runtime.PlainSenders, 5) + "."
		return &Check{State: Risk, Line: line, Details: local, Fix: fix}
	case len(local) > 0:
		fix.Steps = []string{"Give it a new configuration from Add data.", "Then choose Refuse them under Agents on plain HTTP."}
		if f.Runtime.LocalPlainSenders > 1 {
			fix.Steps[0] = "Give them a new configuration from Add data."
		}
		return &Check{State: Attention, Line: local[0], Fix: fix}
	case f.Uptime >= 24*time.Hour:
		return &Check{State: Attention, Line: "Agents on plain HTTP are still accepted, though none has sent that way in the last day.", Fix: fix}
	}
	return &Check{State: Attention, Line: "Agents on plain HTTP are still accepted. None has sent that way since Signalith started " +
		ago(f.Now, f.Now.Add(-f.Uptime)) + ".", Fix: fix}
}

// checkSyslog: transit.syslog.
func checkSyslog(f *Facts) *Check {
	s := f.Config.Syslog
	if !s.Enabled() {
		return nil
	}
	// The plain listeners other computers can reach, and their ports; a
	// listener on a loopback address takes syslog only from this computer.
	var plain, ports, local []string
	for _, l := range []struct{ name, addr string }{{"UDP", s.UDP}, {"TCP", s.TCP}} {
		if l.addr == "" {
			continue
		}
		host, port := listenHost(l.addr)
		if host != "" && isLoopback(host) {
			local = append(local, l.name)
			continue
		}
		plain = append(plain, l.name)
		if s.PublicPort > 0 {
			port = strconv.Itoa(s.PublicPort)
		}
		if port != "" && !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
	}
	var c *Check
	allow := prefixList(s.AllowList())
	portText := "port " + joinAnd(ports)
	if len(ports) > 1 {
		portText = "ports " + joinAnd(ports)
	}
	localLine := "Syslog over " + joinAnd(local) + " is accepted only from this computer."
	switch {
	case len(plain) == 0 && len(local) == 0:
		c = &Check{State: Good, Line: "Syslog arrives only over TLS, so it's encrypted."}
	case len(plain) == 0 && s.TLS != "":
		c = &Check{State: Good, Line: "Syslog over TLS is encrypted, and syslog over " + joinAnd(local) + " is accepted only from this computer."}
	case len(plain) == 0:
		c = &Check{State: Good, Line: "Syslog is accepted only from this computer."}
	case len(allow) > 0:
		c = &Check{State: Good, Line: "Syslog over " + joinAnd(plain) + " is accepted only from " + shorten(allow, 3) +
			". It isn't encrypted, which is normal for devices that can't use TLS."}
		if s.TLS == "" {
			c.Tip = &Fix{Steps: []string{"Devices that can send over TLS, such as rsyslog, syslog-ng and many firewalls, can use syslog over TLS. " +
				"Turn on TLS address, then set them up from Add data > Syslog."}, Setting: "syslog.tls", Docs: doc(docHTTPSAgents)}
		}
	case f.Runtime != nil && f.Runtime.SyslogNATed:
		c = &Check{State: Unknown, Line: "Docker hides syslog senders' real addresses here, so Signalith can't limit who sends. Limit who reaches " +
			portText + " with this computer's firewall.", Fix: &Fix{
			Steps: []string{"Allow only the devices that send syslog to reach " + portText + " in this computer's firewall."},
			Docs:  doc(docSecSyslog)}}
	default:
		c = &Check{State: Attention, Line: "Syslog over " + joinAnd(plain) + " is accepted from any computer that can reach " + portText +
			", so anyone could send fake events.", Fix: &Fix{
			Steps:   []string{"List the addresses or ranges of the devices that send syslog, such as 10.0.0.0/8."},
			Setting: "syslog.allow", Docs: doc(docSecSyslog)}}
	}
	if len(plain) > 0 && len(local) > 0 {
		c.Details = append(c.Details, localLine)
	}
	if f.Runtime != nil && f.Runtime.SyslogSenders != nil {
		var parts []string
		first, total := true, 0
		for _, l := range []struct{ name, proto, addr string }{{"UDP", "udp", s.UDP}, {"TCP", "tcp", s.TCP}, {"TLS", "tls", s.TLS}} {
			if l.addr == "" {
				continue
			}
			n := f.Runtime.SyslogSenders[l.proto]
			total += n
			if first {
				parts = append(parts, itoa(n)+plural(n, " device", " devices")+" over "+l.name)
				first = false
			} else {
				parts = append(parts, itoa(n)+" over "+l.name)
			}
		}
		if total == 0 {
			c.Details = append(c.Details, "No device sent syslog in the last day.")
		} else {
			c.Details = append(c.Details, "In the last day: "+joinAnd(parts)+".")
		}
	}
	return c
}

// checkOpenSearchTransit: transit.opensearch.
func checkOpenSearchTransit(f *Facts) *Check {
	o := f.Config.OpenSearch
	scheme, host, _ := urlParts(o.URL)
	local := isLoopback(host)
	demoLine := "OpenSearch uses the demo certificate it ships with, whose key anyone can download, so it can't prove who it is."
	demoFix := &Fix{Steps: []string{"Replace the demo certificates with your own; signalith opensearch-certs makes them."}, Docs: doc(docOSCerts)}
	httpFix := &Fix{Steps: []string{"Turn on HTTPS in OpenSearch, then change the address to https://."}, Setting: "opensearch.url", Docs: doc(docOSLinux)}
	switch {
	case scheme == "https" && o.TLSSkipVerify:
		fix := &Fix{Steps: []string{"Set CA certificate file to the certificate of the authority that signed OpenSearch's.",
			"Then turn off Skip certificate check, and restart when asked."}, Setting: "opensearch.tls_skip_verify", Docs: doc(docOSPoint)}
		if local {
			return &Check{State: Attention, Line: "Signalith doesn't check OpenSearch's certificate. OpenSearch runs on this computer, so only a program here could pose as it.", Fix: fix}
		}
		return &Check{State: Risk, Line: "Signalith doesn't check OpenSearch's certificate, so someone on the network could pose as OpenSearch and read events and its password.", Fix: fix}
	case scheme != "https" && !local && f.InContainer && f.OpenSearch.SameNetwork:
		return &Check{State: Attention, Line: "Events cross to OpenSearch at " + host + " unencrypted. It's on the same Docker network, so they likely stay on this computer.", Fix: httpFix}
	case scheme != "https" && !local:
		what := "Events"
		if o.Password != "" {
			what = "Events and the OpenSearch password"
		}
		return &Check{State: Risk, Line: what + " cross the network to " + host + " unencrypted.", Fix: httpFix}
	case scheme == "https" && f.OpenSearch.DemoCert && !local:
		return &Check{State: Risk, Line: demoLine, Fix: demoFix}
	case scheme == "https" && f.OpenSearch.DemoCert:
		return &Check{State: Attention, Line: demoLine, Fix: demoFix}
	case scheme == "https":
		return &Check{State: Good, Line: "Signalith reaches OpenSearch over HTTPS and checks its certificate."}
	}
	return &Check{State: Good, Line: "Signalith reaches OpenSearch on this computer, so events never cross the network."}
}

// checkOutbound: transit.outbound.
func checkOutbound(f *Facts) *Check {
	c := f.Config
	if c.Assistant.Provider == "" && len(f.Feeds) == 0 {
		return nil
	}
	var probs []problem
	assistantFix := &Fix{Steps: []string{"Use the assistant's https:// address, if it has one."}, Setting: "assistant.url"}
	feedFix := &Fix{Steps: []string{"Use the feed's https:// address, if it has one."}, Page: &PageLink{ID: "intel", Label: "Open Threat intel"}}
	var good []string
	var tip *Fix
	if c.Assistant.Provider != "" {
		scheme, host, _ := urlParts(c.AssistantURL())
		switch {
		case isLoopback(host):
			good = append(good, "The AI assistant runs on this computer.")
		case scheme == "https":
			good = append(good, "assistant")
		case c.Assistant.APIKey != "":
			probs = append(probs, problem{Risk, "The AI assistant's API key crosses the network to " + host + " unencrypted.", assistantFix})
		default:
			good = append(good, "The AI assistant at "+host+" is reached over plain HTTP, without an API key; only questions and field names go to it.")
			tip = &Fix{Steps: []string{"Serve the AI assistant over HTTPS, so nobody on the network can change its answers."}, Setting: "assistant.url"}
		}
	}
	secure, local := 0, 0
	for _, fd := range f.Feeds {
		scheme, host, _ := urlParts(fd.URL)
		switch {
		case isLoopback(host):
			local++
		case scheme == "https":
			secure++
		case fd.Credentials:
			probs = append(probs, problem{Risk, "Feed " + fd.Name + "'s password or key crosses the network to " + host + " unencrypted.", feedFix})
		default:
			probs = append(probs, problem{Attention, "Feed " + fd.Name + " downloads over plain HTTP, so someone on the network could change what it says.", feedFix})
		}
	}
	if ch := worst(probs); ch != nil {
		return ch
	}
	n := secure + local
	feeds := ""
	if n > 0 {
		how := "over HTTPS"
		if local > 0 && secure > 0 {
			how = "over HTTPS or from this computer"
		} else if local > 0 {
			how = "from this computer"
		}
		feeds = itoa(n) + plural(n, " threat intel feed is", " threat intel feeds are") + " downloaded " + how + "."
	}
	var line string
	switch {
	case len(good) == 1 && good[0] == "assistant" && n > 0 && local == 0:
		line = "The AI assistant and " + itoa(n) + plural(n, " threat intel feed are", " threat intel feeds are") + " reached over HTTPS."
	case len(good) == 1 && good[0] == "assistant":
		line = strings.TrimSpace("The AI assistant is reached over HTTPS. " + feeds)
	case len(good) == 1:
		line = strings.TrimSpace(good[0] + " " + feeds)
	default:
		line = feeds
	}
	return &Check{State: Good, Line: line, Tip: tip}
}

// checkProxies: transit.proxies.
func checkProxies(f *Facts) *Check {
	list := f.Config.Server.TrustedProxyList()
	var legacy []string
	if f.Runtime != nil {
		legacy = f.Runtime.LegacyProxies
	}
	if len(f.Config.Server.TrustedProxies) == 0 && len(legacy) == 0 {
		return nil
	}
	if f.Config.Server.LegacyProxied() {
		// HTTPS is left to that proxy: transit.https says so.
		return nil
	}
	fix := &Fix{Setting: "server.trusted_proxies", Docs: doc(docHTTPSProxy)}
	if len(legacy) > 0 {
		fix.Steps = []string{"List it under Trusted reverse proxies."}
		return &Check{State: Attention, Line: "Signalith believes the reverse proxy at " + shorten(legacy, 3) +
			" only because signalith.yaml was written before HTTPS was the default.", Fix: fix}
	}
	header := f.Config.Server.ClientAddressHeader()
	for _, p := range list {
		if p.Addr().Is4() && p.Bits() < 16 || !p.Addr().Is4() && p.Bits() < 48 {
			fix.Steps = []string{"List only the proxies' own addresses."}
			line := "Trusted reverse proxies includes " + p.String() + ", so any computer in it can claim a browser used HTTPS"
			if header != "" {
				line += ", and choose the address its sign-ins are counted under"
			}
			return &Check{State: Attention, Line: line + ".", Fix: fix}
		}
	}
	if header == "" {
		return &Check{State: Good, Line: "Signalith believes forwarded HTTPS only from " + shorten(prefixList(list), 3) + ".",
			Tip: &Fix{Setting: "server.client_header", Docs: doc(docHTTPSProxy), Steps: []string{
				"Everyone reaching Signalith through these proxies counts as one shared address for the sign-in limits and the log.",
				"If the proxy sets X-Forwarded-For itself, choose it under Client address header, so each person is counted and logged by their own address."}}}
	}
	return &Check{State: Good, Line: "Signalith believes forwarded HTTPS and client addresses (" + header + ") only from " + shorten(prefixList(list), 3) + "."}
}
