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
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/seek-ret/ebpf-training/workshop1/internal/connections"
	"github.com/seek-ret/ebpf-training/workshop1/internal/settings"
	"github.com/seek-ret/ebpf-training/workshop1/internal/structs"
	"log"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
)

// ProbeEventLoop is the signature for the callback functions to extract the events from the input channel.
type ProbeEventLoop func(inputChan chan []byte, connectionFactory *connections.Factory)

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
func (probeChannel *ProbeChannel) Start(module *bpf.Module, connectionFactory *connections.Factory) error {
	probeChannel.eventChannel = make(chan []byte)
	probeChannel.lostEventsChannel = make(chan uint64)

	table := bpf.NewTable(module.TableId(probeChannel.name), module)

	var err error
	probeChannel.perfMap, err = bpf.InitPerfMapWithPageCnt(table, probeChannel.eventChannel, probeChannel.lostEventsChannel, 8192)
	if err != nil {
		return fmt.Errorf("failed to init perf mapping for %q due to: %v", probeChannel.name, err)
	}

	go probeChannel.eventLoop(probeChannel.eventChannel, connectionFactory)
	go func() {
		for {
			<-probeChannel.lostEventsChannel
		}
	}()

	probeChannel.perfMap.Start()
	return nil
}

// LaunchPerfBufferConsumers launches all probe channels.
func LaunchPerfBufferConsumers(module *bpf.Module, connectionFactory *connections.Factory) error {
	for _, probeChannel := range defaultPerfBufferHandlers {
		if err := probeChannel.Start(module, connectionFactory); err != nil {
			return err
		}
	}

	return nil
}

var (
	// defaultPerfBufferHandlers is the default handlers for the events coming from the kernel.
	defaultPerfBufferHandlers = []*ProbeChannel{
		NewProbeChannel("socket_data_events", socketDataEventCallback),
		NewProbeChannel("socket_open_events", socketOpenEventCallback),
		NewProbeChannel("socket_close_events", socketCloseEventCallback),
	}

	eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEventAttr{}))
)

func socketDataEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		if len(data) < eventAttributesSize {
			log.Printf("Buffer's for SocketDataEvent is smaller (%d) than the minimum required (%d)", len(data), eventAttributesSize)
			continue
		} else if len(data) > structs.EventBodyMaxSize+eventAttributesSize {
			log.Printf("Buffer's for SocketDataEvent is bigger (%d) than the maximum for the struct (%d)", len(data), structs.EventBodyMaxSize+eventAttributesSize)
			continue
		}
		var event structs.SocketDataEvent

		// binary.Read require the input data to be at the same size of the object.
		// Since the Msg field might be mostly empty, binary.read fails.
		// So we split the loading into the fixed size attribute parts, and copying the message separately.
		if err := binary.Read(bytes.NewReader(data[:eventAttributesSize]), bpf.GetHostByteOrder(), &event.Attr); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}

		// If there is at least single byte over the required minimum, thus we should copy it.
		if len(data) > eventAttributesSize {
			copy(event.Msg[:], data[eventAttributesSize:eventAttributesSize+int(event.Attr.MsgSize)])
		}
		event.Attr.TimestampNano += settings.GetRealTimeOffset()
		connectionFactory.GetOrCreate(event.Attr.ConnID).AddDataEvent(event)
	}
}

func socketOpenEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketOpenEvent

		if err := binary.Read(bytes.NewReader(data), bpf.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}
		event.TimestampNano += settings.GetRealTimeOffset()
		connectionFactory.GetOrCreate(event.ConnID).AddOpenEvent(event)
	}
}

func socketCloseEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketCloseEvent
		if err := binary.Read(bytes.NewReader(data), bpf.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}
		event.TimestampNano += settings.GetRealTimeOffset()
		connectionFactory.GetOrCreate(event.ConnID).AddCloseEvent(event)
	}
}
