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

package structs

// ConnID is a conversion of the following C-Struct into GO.
// struct conn_id_t {
//    uint32_t tgid;
//    int32_t fd;
//    uint64_t tsid;
// };.
type ConnID struct {
	TGID uint32
	FD   int32
	TsID uint64
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
	Pos           uint64
}

const (
	EventBodyMaxSize = 30720
)

// SocketDataEvent is a conversion of the following C-Struct into GO.
// struct socket_data_event_t {
//    struct attr_t attr;
//    char msg[30720];
// };.
type SocketDataEvent struct {
	Attr SocketDataEventAttr
	Msg  [EventBodyMaxSize]byte
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
	Addr          SockAddrIn
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
	WrittenBytes  int64
	ReadBytes     int64
}
