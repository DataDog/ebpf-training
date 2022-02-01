// Count incoming packets on XDP layer per protocol type.

// Based on https://github.com/iovisor/gobpf/blob/master/examples/bcc/xdp/xdp_drop.go (2017 GustavoKatel)
// Licensed under the Apache License, Version 2.0 (the "License")

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

/*
#include <bcc/libbpf.h>
*/
import "C"

const (
	numberOfArguments  = 2
	bpfDefaultLogLevel = 1
	bpfLogSize         = 65536
)

// protocols is a mapping between a protocol number to its string representation
var protocols = map[uint32]string{
	1:  "icmp",
	2:  "igmp",
	6:  "tcp",
	17: "udp",
	58: "ipv6-icmp",
}

func main() {
	if len(os.Args) != numberOfArguments+1 {
		usage()
	}

	bpfSourceCodeFile := os.Args[1]
	bpfSourceCodeContent, err := ioutil.ReadFile(bpfSourceCodeFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read bpf source code file %s with error: %v\n", bpfSourceCodeFile, err)
		os.Exit(1)
	}

	fmt.Println("Loading and attaching the XDP program")

	module := bcc.NewModule(string(bpfSourceCodeContent), nil)
	defer module.Close()

	fn, err := module.Load("xdp_counter", C.BPF_PROG_TYPE_XDP, bpfDefaultLogLevel, bpfLogSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load XDP program: %v\n", err)
		os.Exit(1)
	}

	device := os.Args[2]
	err = module.AttachXDP(device, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach XDP program: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()

	fmt.Println("Counting packets, hit CTRL+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	protocolCounter := bcc.NewTable(module.TableId("protocol_counter"), module)

	<-sig

	fmt.Printf("\n{IP protocol}: {total number of packets}\n")
	for it := protocolCounter.Iter(); it.Next(); {
		key := protocols[bcc.GetHostByteOrder().Uint32(it.Key())]
		if key == "" {
			key = "Unknown"
		}
		value := bcc.GetHostByteOrder().Uint64(it.Leaf())

		if value > 0 {
			fmt.Printf("%v: %v packets\n", key, value)
		}
	}
}

func usage() {
	fmt.Printf("Usage: sudo %v <xdp bpf code> <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: sudo %v xdp_prog.c lo\n", os.Args[0])
	os.Exit(1)
}
