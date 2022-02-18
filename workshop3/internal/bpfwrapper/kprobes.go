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
 * SPDX-License-Identifier: Apache-2.0.
 */

package bpfwrapper

import (
	"fmt"
	"github.com/iovisor/gobpf/bcc"
	"log"
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
func AttachKprobes(bpfModule *bcc.Module, kprobeList []Kprobe) error {
	for _, probe := range kprobeList {
		functionToHook := probe.FunctionToHook
		if probe.IsSyscall {
			functionToHook = bcc.GetSyscallFnName(probe.FunctionToHook)
		}

		probeFD, err := bpfModule.LoadKprobe(probe.HookName)
		if err != nil {
			return fmt.Errorf("failed to load %q due to: %v", probe.HookName, err)
		}

		switch probe.Type {
		case EntryType:
			log.Printf("Loading %q for %q as kprobe\n", probe.HookName, probe.FunctionToHook)
			if err = bpfModule.AttachKprobe(functionToHook, probeFD, maxActiveConnections); err != nil {
				return fmt.Errorf("failed to attach kprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		case ReturnType:
			log.Printf("Loading %q for %q as kretprobe\n", probe.HookName, probe.FunctionToHook)
			if err = bpfModule.AttachKretprobe(functionToHook, probeFD, maxActiveConnections); err != nil {
				return fmt.Errorf("failed to attach kretprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		default:
			return fmt.Errorf("unknown Kprobe type %d given for %q", probe.Type, probe.HookName)
		}
	}
	return nil
}
