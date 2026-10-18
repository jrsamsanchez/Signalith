//go:build windows

package agentd

import (
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// windowsName is Windows' name for itself, such as "Windows 11 Pro 24H2
// (build 26100)" or "Windows Server 2022 Datacenter (build 20348)".
func windowsName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	product, _, _ := k.GetStringValue("ProductName")
	display, _, _ := k.GetStringValue("DisplayVersion")
	build, _, _ := k.GetStringValue("CurrentBuild")
	return windowsDisplayName(product, display, build)
}

// windowsDisplayName puts the registry's values together. Windows 11
// still calls itself Windows 10 in ProductName; its build numbers start
// at 22000.
func windowsDisplayName(product, display, build string) string {
	if product == "" {
		return ""
	}
	if n, err := strconv.Atoi(build); err == nil && n >= 22000 && strings.HasPrefix(product, "Windows 10") {
		product = "Windows 11" + strings.TrimPrefix(product, "Windows 10")
	}
	name := product
	if display != "" {
		name += " " + display
	}
	if build != "" {
		name += " (build " + build + ")"
	}
	return oneLine(name)
}
