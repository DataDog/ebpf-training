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

package structs

import "unsafe"

// ConnID is a conversion of the following C-Struct into GO.
// struct conn_id_t {
//    uint32_t tgid;
//    int32_t fd;
// };.
type ConnID struct {
	TGID uint32
	FD   int32
}

// SockAddr is a conversion of the following C-Struct into GO.
// struct sockaddr {
//    unsigned short int sa_family;
//    char sa_data[14];
// };.
type SockAddr struct {
	SaFamily uint16
	SaData   [14]byte
}

// SockAddrIn is a conversion of the following C-Struct into GO.
// struct sockaddr_in {
//    unsigned short int sin_family;
//    uint16_t sin_port;
//    struct in_addr sin_addr;
//
//    /* _to size of `struct sockaddr'.  */
//    unsigned char sin_zero[8];
// };.
type SockAddrIn struct {
	SinFamily uint16
	SinPort   uint16
	SinAddr   uint32
	SinZero   [8]byte
}

// SockAddrIn6 is a conversion of the following C-Struct into GO.
// struct sockaddr_in6 {
//    unsigned short int sin6_family;
//    uint16_t sin6_port;	/* Transport layer port # */
//    uint32_t sin6_flowinfo;	/* IPv6 flow information */
//    struct in6_addr sin6_addr;	/* IPv6 address */
//    uint32_t sin6_scope_id;	/* IPv6 scope-id */
// };.
type SockAddrIn6 struct {
	Sin6Family   uint16
	Sin6Port     uint16
	Sin6FlowInfo uint32
	Sin6Addr     [16]byte
	Sin6ScopeID  uint32
}

// SockAddrUnion is a conversion of the following C-union into GO.
// It is a byte array with the max length of the structs (specifically, SockAddrIn6).
// union sockaddr_t {
//    struct sockaddr sa;
//    struct sockaddr_in in4;
//    struct sockaddr_in6 in6;
// };.
type SockAddrUnion [28]byte

func (s *SockAddrUnion) Fill(other SockAddrUnion) {
	copy(s[:], other[:])
}

func (s *SockAddrUnion) FillBytes(arr []byte) {
	copy(s[:], arr)
}

// Sa returns the sockaddr conversion of the union.
func (s *SockAddrUnion) Sa() *SockAddr {
	return (*SockAddr)(unsafe.Pointer(s))
}

// In4 returns the sockaddr_in conversion of the union.
func (s *SockAddrUnion) In4() *SockAddrIn {
	return (*SockAddrIn)(unsafe.Pointer(s))
}

// In6 returns the sockaddr_in6 conversion of the union.
func (s *SockAddrUnion) In6() *SockAddrIn6 {
	return (*SockAddrIn6)(unsafe.Pointer(s))
}

// SocketDataEventAttr is a conversion of the following C-Struct into GO.
// struct attr_t {
//     uint64_t timestamp_ns;
//     struct conn_id_t conn_id;
//     enum traffic_direction_t direction;
//     uint32_t msg_size;
//     uint64_t pos;
// };.
type SocketDataEventAttr struct {
	TimestampNano uint64
	ConnID        ConnID
	Direction     TrafficDirectionEnum
	MsgSize       uint32
}

type SocketDataEvent struct {
	Attr SocketDataEventAttr
	Msg  [399]byte
}

// SocketOpenEvent is a conversion of the following C-Struct into GO.
// struct socket_open_event_t {
//    uint64_t timestamp_ns;
//    struct conn_id_t conn_id;
//    struct sockaddr_in* addr;
//};.
type SocketOpenEvent struct {
	TimestampNano uint64
	ConnID        ConnID
	Addr          SockAddrUnion
}

// SocketCloseEvent is a conversion of the following C-Struct into GO.
// struct socket_control_event_t {
//    uint64_t timestamp_ns;
//    struct conn_id_t conn_id;
//    int64_t wr_bytes;
//    int64_t rd_bytes;
//};.
type SocketCloseEvent struct {
	TimestampNano uint64
	ConnID        ConnID
}
