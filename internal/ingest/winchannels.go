package ingest

import (
	"strings"
	"unicode"
)

// FirewallChannel is where Windows Defender Firewall logs its rules and
// settings being changed.
const FirewallChannel = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"

// AppxChannel is where Windows logs app packages (MSIX and AppX) being
// installed, and blocked.
const AppxChannel = "Microsoft-Windows-AppXDeploymentServer/Operational"

// WmiChannel is where WMI logs failed operations and permanent event
// subscriptions.
const WmiChannel = "Microsoft-Windows-WMI-Activity/Operational"

// BitsChannel is where the Background Intelligent Transfer Service logs
// its download and upload jobs.
const BitsChannel = "Microsoft-Windows-Bits-Client/Operational"

// namedChannel is a Windows log whose events the parser reads by name:
// the prefix of its stored fields, and its events.
type namedChannel struct {
	prefix string
	events map[string]systemEvent
}

// firewallRule is the data of a firewall rule added (2004; 2071 and 2097
// on Windows 11 add ErrorCode, and 2097 PolicyAppId before it).
var firewallRule = []string{"RuleId", "RuleName", "Origin", "ApplicationPath", "ServiceName", "Direction", "Protocol",
	"LocalPorts", "RemotePorts", "Action", "Profiles", "LocalAddresses", "RemoteAddresses", "RemoteMachineAuthorizationList",
	"RemoteUserAuthorizationList", "EmbeddedContext", "Flags", "Active", "EdgeTraversal", "LooseSourceMapped",
	"SecurityOptions", "ModifyingUser", "ModifyingApplication", "SchemaVersion", "RuleStatus", "LocalOnlyMapped"}

// appxDeployment is the data of a package deployed (400); a deployment
// failed (401) adds the error and its details.
var appxDeployment = []string{"DeploymentOperation", "PackageFullName", "Path", "MountPoint", "TargetPlatform", "SystemVolume",
	"StorageId", "IsCentennial", "PackageType", "IsPackageEncrypted", "DeploymentOptions", "IsStreamingPackage", "IsInRelatedSet",
	"IsPackageUsingBDC", "MainPackageFamilyName", "CallingProcess", "IsOptional", "PackageFlags", "PackageFlags2", "HasWin32alacarte",
	"HasFullTrust", "ExternalLocation", "PackageSourceUri", "PackageDisplayName"}

var appxDeploymentFailed = []string{"DeploymentOperation", "PackageFullName", "Path", "ErrorCode", "MountPoint", "TargetPlatform",
	"SystemVolume", "StorageId", "IsCentennial", "PackageType", "IsPackageEncrypted", "DeploymentOptions", "IsStreamingPackage",
	"IsInRelatedSet", "IsPackageUsingBDC", "MainPackageFamilyName", "CallingProcess", "IsInPlaceUpdate", "ErrorFileInfo",
	"DetailedMessageInfo", "RollbackErrorFileInfo", "RollbackDetailedMessageInfo", "IsOptional", "PackageFlags", "PackageFlags2",
	"HasWin32alacarte", "HasFullTrust", "ExternalLocation", "PackageSourceUri", "PackageDisplayName"}

// namedChannels are the Windows logs, besides the System log, whose
// events the parser keeps the data of by name, by channel (lower case):
// each value of an event is stored as ChannelDataField names it. The
// names and their order are the events' templates in Windows' own
// manifests (Windows 10 and 11, Server 2022).
var namedChannels = map[string]namedChannel{
	strings.ToLower(FirewallChannel): {"firewall", map[string]systemEvent{
		"2002": {"A firewall setting changed", []string{"SettingType", "SettingValueSize", "SettingValue", "SettingValueDisplay", "Origin", "ModifyingUser", "ModifyingApplication"}},
		"2083": {"A firewall setting changed", []string{"SettingType", "SettingValueSize", "SettingValue", "SettingValueDisplay", "Origin", "ModifyingUser", "ModifyingApplication", "ErrorCode"}},
		"2003": {"A firewall profile setting changed", []string{"Profiles", "SettingType", "SettingValueSize", "SettingValue", "SettingValueString", "Origin", "ModifyingUser", "ModifyingApplication"}},
		"2082": {"A firewall profile setting changed", []string{"Profiles", "SettingType", "SettingValueSize", "SettingValue", "SettingValueString", "Origin", "ModifyingUser", "ModifyingApplication", "ErrorCode"}},
		"2004": {"A firewall rule was added", firewallRule},
		"2071": {"A firewall rule was added", append(firewallRule[:len(firewallRule):len(firewallRule)], "ErrorCode")},
		"2097": {"A firewall rule was added", append(firewallRule[:len(firewallRule):len(firewallRule)], "PolicyAppId", "ErrorCode")},
		"2006": {"A firewall rule was deleted", []string{"RuleId", "RuleName", "ModifyingUser", "ModifyingApplication"}},
		"2052": {"A firewall rule was deleted", []string{"RuleId", "RuleName", "ModifyingUser", "ModifyingApplication", "ErrorCode"}},
		"2008": {"Firewall Group Policy settings changed", nil},
		"2009": {"The firewall could not load Group Policy", []string{"ErrorCode"}},
		"2032": {"The firewall was reset to its defaults", []string{"ModifyingUser", "ModifyingApplication"}},
		"2060": {"The firewall was reset to its defaults", []string{"ModifyingUser", "ModifyingApplication", "ErrorCode"}},
		"2033": {"All firewall rules were deleted", []string{"Store Type", "ModifyingUser", "ModifyingApplication"}},
		"2059": {"All firewall rules were deleted", []string{"Store Type", "ModifyingUser", "ModifyingApplication", "ErrorCode"}},
	}},
	strings.ToLower(AppxChannel): {"appx", map[string]systemEvent{
		"400": {"An app package was deployed", appxDeployment},
		"401": {"An app package deployment failed", appxDeploymentFailed},
		"412": {"AppLocker blocked an app package", []string{"PackageFullName", "ErrorCode"}},
		"441": {"A policy blocked an app package deployment in a special profile", nil},
		"442": {"A policy blocked an app package deployment to a non-system volume", []string{"PackageFullName", "MountPoint"}},
		"453": {"A platform policy blocked an app package", []string{"PackageFullName", "PolicyReason"}},
		"454": {"A platform policy blocked an app package", []string{"PackageFullName", "PolicyReason"}},
		"603": {"An app package deployment was started", []string{"DeploymentOperation", "Path", "Flags", "FlagsHigh", "CallingProcess", "ExternalLocation"}},
		"854": {"An app package file was downloaded", []string{"Path"}},
	}},
	strings.ToLower(WmiChannel): {"wmi", map[string]systemEvent{
		"5858": {"A WMI operation failed", []string{"Id", "ClientMachine", "User", "ClientProcessId", "Component", "Operation", "ResultCode", "PossibleCause"}},
		"5859": {"A WMI event filter was registered", []string{"NamespaceName", "Query", "User", "processid", "providerName", "queryid", "PossibleCause"}},
		"5861": {"A WMI permanent event subscription was registered", []string{"Namespace", "ESS", "CONSUMER", "PossibleCause"}},
	}},
	strings.ToLower(BitsChannel): {"bits", map[string]systemEvent{
		"3": {"A BITS job was created", []string{"jobTitle", "jobId", "jobOwner", "processPath", "processId", "ClientProcessStartKey"}},
		"16403": {"A BITS transfer started", []string{"User", "jobTitle", "jobId", "jobOwner", "fileCount", "RemoteName", "LocalName",
			"processId", "ClientProcessStartKey"}},
	}},
}

// NamedChannelServices are the Sigma log source services of the logs
// namedChannels lists, and their channels.
var NamedChannelServices = map[string]string{
	"firewall-as":           FirewallChannel,
	"bits-client":           BitsChannel,
	"appxdeployment-server": AppxChannel,
	"wmi":                   WmiChannel,
}

// NamedChannelCategory is the category of the Sigma rules of a log
// NamedChannelServices lists: its service with _ for - (firewall_as).
func NamedChannelCategory(service string) string {
	return strings.ReplaceAll(strings.ToLower(service), "-", "_")
}

// namedChannelFor is the log of a channel whose events the parser reads
// by name.
func namedChannelFor(channel string) (namedChannel, bool) {
	c, ok := namedChannels[strings.ToLower(channel)]
	return c, ok
}

// namedChannelEvent is an event of such a log.
func namedChannelEvent(channel, eventID string) (systemEvent, bool) {
	c, ok := namedChannelFor(channel)
	if !ok {
		return systemEvent{}, false
	}
	e, ok := c.events[eventID]
	return e, ok
}

// IsNamedChannel reports whether the parser reads a channel's events by
// name (ChannelDataField).
func IsNamedChannel(channel string) bool {
	_, ok := namedChannelFor(channel)
	return ok
}

// ChannelDataField is the stored field of a data value of a channel's
// events (a firewall rule's ApplicationPath is firewall_application_path,
// a BITS job's processPath bits_process_path), for the channels and
// events the parser reads by name. The name is matched without case, as
// Sigma does.
func ChannelDataField(channel, name string) (string, bool) {
	c, ok := namedChannelFor(channel)
	if !ok {
		return "", false
	}
	for _, e := range c.events {
		for _, n := range e.data {
			if strings.EqualFold(n, name) {
				return snakeField(c.prefix, n), true
			}
		}
	}
	return "", false
}

// snakeField is a prefix, _ and a data value's name in snake case
// (RuleId is rule_id, Store Type store_type).
func snakeField(prefix, name string) string {
	var b strings.Builder
	b.WriteString(prefix)
	b.WriteByte('_')
	prev := rune(0)
	for i, r := range name {
		switch {
		case r == ' ':
			b.WriteByte('_')
		case unicode.IsUpper(r) && i > 0 && !unicode.IsUpper(prev) && prev != ' ':
			b.WriteByte('_')
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteRune(unicode.ToLower(r))
		}
		prev = r
	}
	return b.String()
}

// namedChannelFields are the fields ChannelDataField names.
var namedChannelFields = func() map[string]bool {
	out := map[string]bool{}
	for _, c := range namedChannels {
		for _, e := range c.events {
			for _, n := range e.data {
				out[snakeField(c.prefix, n)] = true
			}
		}
	}
	return out
}()

// parseNamedChannel keeps a provider and the data of an event of a log
// namedChannels lists, by name; the event stays in Other, found by its
// channel (sourcetype) and ID.
func parseNamedChannel(channel, eventID, provider string, in []string, ev *Event) {
	f := ev.Fields
	if provider != "" {
		f["provider"] = provider
	}
	c, _ := namedChannelFor(channel)
	e, ok := c.events[eventID]
	if !ok {
		return
	}
	f["signature"] = e.signature
	for i, n := range e.data {
		if v := strings.TrimSpace(at(in, i)); v != "" {
			f[snakeField(c.prefix, n)] = v
		}
	}
}
