// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

// checkMemory: use.memory.
func checkMemory(f *Facts) *Check {
	m := f.Memory
	switch f.Server.OS {
	case "linux", "windows":
	default:
		return &Check{State: Unknown, Line: "Signalith can check this only on Linux and Windows.",
			Fix: &Fix{Steps: []string{"Make sure crash dumps are off for Signalith on this computer."}, Docs: doc(docEncInUse)}}
	}
	if !m.Known {
		why := f.Process.Why
		if why == "" {
			why = "Signalith couldn't read how its process is set up."
		}
		fix := processFix(f.Process)
		if fix == nil {
			fix = &Fix{}
		}
		fix.Docs = doc(docEncInUse)
		return &Check{State: Unknown, Line: why, Fix: fix}
	}
	if f.Server.OS == "windows" {
		if m.FullDumps {
			folder := m.DumpFolder
			if folder == "" {
				folder = `%LOCALAPPDATA%\CrashDumps`
			}
			return &Check{State: Attention, Line: "Windows is set to keep full memory dumps of crashing programs in " + folder +
				", which could hold passwords Signalith has in memory.", Fix: &Fix{
				Steps: []string{"Ask whoever set up crash dumps on this computer to leave out signalith.exe, or remove the LocalDumps setting at " + m.DumpsRegistry + "."},
				Docs:  doc(docEncInUse)}}
		}
		return &Check{State: Good, Line: "Windows isn't set to keep full memory dumps of Signalith if it crashes."}
	}
	if !m.CoreOff || !m.NotDumpable {
		return &Check{State: Attention, Line: "Signalith's memory could be saved in a crash dump, with passwords in it.", Fix: &Fix{
			Steps: []string{"Restart Signalith with this version, which turns crash dumps off. Under systemd, keep LimitCORE=0 in the unit."},
			Docs:  doc(docEncInUse)}}
	}
	c := &Check{State: Good, Line: "Signalith's memory can't be saved in a crash dump, and other programs can't read it, except as root."}
	switch {
	case !m.SwapOn || m.SwapOffForUs:
		c.Details = []string{"Swap: off for Signalith."}
	case m.SwapEncrypted:
		c.Details = []string{"Swap: on, encrypted."}
	default:
		c.Details = []string{"Swap: on, so the system could write Signalith's memory to disk."}
	}
	var tip []string
	if m.SwapOn && !m.SwapEncrypted && !m.SwapOffForUs {
		if f.InContainer {
			tip = append(tip, "Swap is on and not encrypted. Set memswap_limit equal to mem_limit for the signalith service, or encrypt swap on the computer that runs Docker.")
		} else {
			tip = append(tip, "Swap is on and not encrypted. The systemd unit turns swap off for Signalith (MemorySwapMax=0); install the current unit, or encrypt swap.")
		}
	}
	if f.ConfidentialVM == "" {
		tip = append(tip, "For more protection, run Signalith in a confidential virtual machine (AMD SEV-SNP or Intel TDX), which is built to keep even its host from reading its memory.")
	}
	if len(tip) > 0 {
		c.Tip = &Fix{Steps: tip, Docs: doc(docEncInUse)}
	}
	return c
}

// checkConfidentialVM: use.confidential_vm, only when one is found.
func checkConfidentialVM(f *Facts) *Check {
	if f.ConfidentialVM == "" {
		return nil
	}
	return &Check{State: Good, Line: "This server runs in a confidential virtual machine (" + f.ConfidentialVM + "), built to keep even its host from reading its memory."}
}
