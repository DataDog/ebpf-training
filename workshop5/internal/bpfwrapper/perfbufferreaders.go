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
	bpf "github.com/iovisor/gobpf/bcc"
)

// ProbeEventLoop is the signature for the callback functions to extract the events from the input channel.
type ProbeEventLoop func(inputChan chan []byte)

// ProbeChannel represents a single handler to a channel of events in the BPF.
type ProbeChannel struct {
	// Name of the BPF channel.
	name string
	// Event loop handler, a method which receive a channel for the input events from the implementation, and parse them.
	eventLoop ProbeEventLoop
	// A go channel which holds the messages from the BPF module.
	eventChannel chan []byte
	// A go channel for lost events.
	lostEventsChannel chan uint64
	// The bpf perf map that links our user mode channel to the BPF module.
	perfMap *bpf.PerfMap
}

// NewProbeChannel creates a new probe channel with the given handle for the given bpf channel name.
func NewProbeChannel(name string, handler ProbeEventLoop) *ProbeChannel {
	return &ProbeChannel{
		name:      name,
		eventLoop: handler,
	}
}

// Start initiate a goroutine for the event loop handler, for a lost events messages and the perf map.
func (probeChannel *ProbeChannel) Start(module *bpf.Module) error {
	probeChannel.eventChannel = make(chan []byte)
	probeChannel.lostEventsChannel = make(chan uint64)

	table := bpf.NewTable(module.TableId(probeChannel.name), module)

	var err error
	probeChannel.perfMap, err = bpf.InitPerfMapWithPageCnt(table, probeChannel.eventChannel, probeChannel.lostEventsChannel, 8192)
	if err != nil {
		return fmt.Errorf("failed to init perf mapping for %q due to: %v", probeChannel.name, err)
	}

	go probeChannel.eventLoop(probeChannel.eventChannel)
	go func() {
		for {
			<-probeChannel.lostEventsChannel
		}
	}()

	probeChannel.perfMap.Start()
	return nil
}

// LaunchPerfBufferConsumers launches all probe channels.
func LaunchPerfBufferConsumers(module *bpf.Module, probeList []*ProbeChannel) error {
	for _, probeChannel := range probeList {
		if err := probeChannel.Start(module); err != nil {
			return err
		}
	}

	return nil
}
