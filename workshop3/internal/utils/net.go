package utils

import (
	"bytes"
	"encoding/binary"
	"github.com/seek-ret/ebpf-training/workshop3/internal/structs"
	"net"
)

func ParseIP(data structs.SockAddrUnion) net.IP {
	if data.Sa().SaFamily == 10 {
		// ipv6
		ip := make(net.IP, net.IPv6len)
		binary.Read(bytes.NewReader(data.In6().Sin6Addr[:]), binary.LittleEndian, &ip)
		return ip
	}

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, data.In4().SinAddr)
	return ip
}

func ParsePort(data structs.SockAddrUnion) uint16 {
	var originalPort uint16
	if data.Sa().SaFamily == 10 {
		// ipv6
		originalPort = data.In6().Sin6Port
	} else {
		originalPort = data.In4().SinPort
	}


	portAsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portAsBytes, originalPort)
	var port2 uint16
	binary.Read(bytes.NewReader(portAsBytes), binary.LittleEndian, &port2)

	return port2
}
