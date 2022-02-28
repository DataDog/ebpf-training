package bpfwrapper

import (
	"fmt"
	"github.com/iovisor/gobpf/bcc"
	"log"
)

// ProbeType represents whether the probe is an entry or a return.
type ProbeType int

const (
	EntryType  ProbeType = 0
	ReturnType ProbeType = 1

)

// Uprobe represents a single uprobe hook.
type Uprobe struct {
	// The name of the function to hook.
	FunctionToHook string
	// The name of the hook function.
	HookName string
	// Whether an uprobe or ret-uprobe.
	Type ProbeType
	// Whether the function to hook is syscall or not.
	BinaryPath string
}

// AttachUprobes attaches the given uprobe list.
func AttachUprobes(soPath string, pid int, bpfModule *bcc.Module, kprobeList []Uprobe) error {
	for _, probe := range kprobeList {
		functionToHook := probe.FunctionToHook

		probeFD, err := bpfModule.LoadUprobe(probe.HookName)
		if err != nil {
			return fmt.Errorf("failed to load %q due to: %v", probe.HookName, err)
		}

		switch probe.Type {
		case EntryType:
			log.Printf("Loading %q for %q as kprobe\n", probe.HookName, probe.FunctionToHook)
			if err = bpfModule.AttachUprobe(soPath, functionToHook, probeFD, pid); err != nil {
				return fmt.Errorf("failed to attach kprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		case ReturnType:
			log.Printf("Loading %q for %q as kretprobe\n", probe.HookName, probe.FunctionToHook)
			if err = bpfModule.AttachUretprobe(soPath, functionToHook, probeFD, pid); err != nil {
				return fmt.Errorf("failed to attach kretprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		default:
			return fmt.Errorf("unknown uprobe type %d given for %q", probe.Type, probe.HookName)
		}
	}
	return nil
}
