/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package bpfwrapper

import (
	"fmt"
	"log"

	bpf "github.com/iovisor/gobpf/bcc"
)

const (
	maxActiveConnections = 1024
)

// ProbeType represents whether the probe is an entry or a return.
type ProbeType int

const (
	EntryType  ProbeType = 0
	ReturnType ProbeType = 1
)

// Kprobe represents a single Kprobe hook.
type Kprobe struct {
	// The name of the function to hook.
	FunctionToHook string
	// The name of the hook function.
	HookName string
	// Whether a Kprobe or ret-Kprobe.
	Type ProbeType
	// Whether the function to hook is syscall or not.
	IsSyscall bool
}

// AttachKprobes attaches the given Kprobe list.
func AttachKprobes(bpfModule *bpf.Module) error {
	for _, probe := range defaultKprobes {
		log.Printf("Loading %q for %q as %d\n", probe.HookName, probe.FunctionToHook, probe.Type)
		functionToHook := probe.FunctionToHook
		if probe.IsSyscall {
			functionToHook = bpf.GetSyscallFnName(probe.FunctionToHook)
		}

		probeFD, err := bpfModule.LoadKprobe(probe.HookName)
		if err != nil {
			return fmt.Errorf("failed to load %q due to: %v", probe.HookName, err)
		}

		switch probe.Type {
		case EntryType:
			if err = bpfModule.AttachKprobe(functionToHook, probeFD, maxActiveConnections); err != nil {
				return fmt.Errorf("failed to attach kprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		case ReturnType:
			if err = bpfModule.AttachKretprobe(functionToHook, probeFD, maxActiveConnections); err != nil {
				return fmt.Errorf("failed to attach kretprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		default:
			return fmt.Errorf("unknown Kprobe type %d given for %q", probe.Type, probe.HookName)
		}
	}
	return nil
}

var (
	// defaultKprobes is the default kprobes to attach.
	defaultKprobes = []Kprobe{
		{
			FunctionToHook: "accept",
			HookName:       "syscall__probe_entry_accept",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept",
			HookName:       "syscall__probe_ret_accept",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept4",
			HookName:       "syscall__probe_entry_accept4",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept4",
			HookName:       "syscall__probe_ret_accept4",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "write",
			HookName:       "syscall__probe_entry_write",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "write",
			HookName:       "syscall__probe_ret_write",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "read",
			HookName:       "syscall__probe_entry_read",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "read",
			HookName:       "syscall__probe_ret_read",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "close",
			HookName:       "syscall__probe_entry_close",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "close",
			HookName:       "syscall__probe_ret_close",
			Type:           ReturnType,
			IsSyscall:      true,
		},
	}
)