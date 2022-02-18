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

package connections

import (
	"log"
	"sync"

	"github.com/seek-ret/ebpf-training/workshop3/internal/structs"
)

const (
	maxBufferSize = 100 * 1024 // 100KB
)

type Tracker struct {
	connID structs.ConnID

	addr           structs.SockAddrUnion
	openTimestamp  uint64
	closeTimestamp uint64

	// Indicates the tracker stopped tracking due to closing the session.
	sentBytes             uint64
	recvBytes             uint64

	recvBuf []byte
	sentBuf []byte
	mutex   sync.RWMutex
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:  connID,
		recvBuf: make([]byte, 0, maxBufferSize),
		sentBuf: make([]byte, 0, maxBufferSize),
		mutex:   sync.RWMutex{},
	}
}

func (conn *Tracker) IsComplete() bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	return conn.closeTimestamp != 0
}

func (conn *Tracker) AddDataEvent(event structs.SocketDataEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	switch event.Attr.Direction {
	case structs.EgressTraffic:
		conn.sentBuf = append(conn.sentBuf, event.Msg[:event.Attr.MsgSize]...)
		conn.sentBytes += uint64(event.Attr.MsgSize)
	case structs.IngressTraffic:
		conn.recvBuf = append(conn.recvBuf, event.Msg[:event.Attr.MsgSize]...)
		conn.recvBytes += uint64(event.Attr.MsgSize)
	default:
	}
}

func (conn *Tracker) AddOpenEvent(event structs.SocketOpenEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	conn.addr = event.Addr
	if conn.openTimestamp != 0 && conn.openTimestamp != event.TimestampNano {
		log.Printf("Changed open info timestamp from %v to %v", conn.openTimestamp, event.TimestampNano)
	}
	conn.openTimestamp = event.TimestampNano
}

func (conn *Tracker) AddCloseEvent(event structs.SocketCloseEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	conn.closeTimestamp = event.TimestampNano
}

