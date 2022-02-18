package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/alexflint/go-arg"
	"github.com/seek-ret/ebpf-training/workshop3/internal/bpfwrapper"
	"github.com/seek-ret/ebpf-training/workshop3/internal/connections"
	"github.com/seek-ret/ebpf-training/workshop3/internal/settings"
	"github.com/seek-ret/ebpf-training/workshop3/internal/structs"
	"github.com/seek-ret/ebpf-training/workshop3/internal/utils"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"

	"github.com/seek-ret/ebpf-training/workshop3/internal/privileges"
)

var (
	level1hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "accept4",
			HookName:       "syscall__probe_entry_accept4",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept4",
			HookName:       "syscall__probe_ret_accept4",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}

	level2hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "read",
			HookName:       "syscall__probe_entry_read",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "read",
			HookName:       "syscall__probe_ret_read",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}

	level3hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "write",
			HookName:       "syscall__probe_entry_write",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "write",
			HookName:       "syscall__probe_ret_write",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}

	level4hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "close",
			HookName:       "syscall__probe_entry_close",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "close",
			HookName:       "syscall__probe_ret_close",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}
)

// args represents the command line arguments.
var args struct {
	BPFFile string `arg:"required,positional"`
	Verbose bool   `arg:"--verbose"`
	Level   int    `arg:"--level,required"`
}

var (
	eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEventAttr{}))
)

func socketDataEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketDataEvent

		// binary.Read require the input data to be at the same size of the object.
		// Since the Msg field might be mostly empty, binary.read fails.
		// So we split the loading into the fixed size attribute parts, and copying the message separately.
		if err := binary.Read(bytes.NewReader(data[:eventAttributesSize]), bcc.GetHostByteOrder(), &event.Attr); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}

		// If there is at least single byte over the required minimum, thus we should copy it.
		if len(data) > eventAttributesSize {
			copy(event.Msg[:], data[eventAttributesSize:eventAttributesSize+int(event.Attr.MsgSize)])
		}
		event.Attr.TimestampNano += settings.GetRealTimeOffset()
		connectionFactory.GetOrCreate(event.Attr.ConnID).AddDataEvent(event)

		if settings.DebugLog {
			direction := "ingress"
			if event.Attr.Direction == structs.EgressTraffic {
				direction = "egress"
			}
			fmt.Println("<------------")
			fmt.Printf("Got %s data event of size %d, with data: \n\n%s\n", direction, event.Attr.MsgSize, event.Msg[:event.Attr.MsgSize])
			fmt.Println("------------>")
		}
	}
}

func socketOpenEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketOpenEvent

		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}
		event.TimestampNano += settings.GetRealTimeOffset()
		connectionFactory.GetOrCreate(event.ConnID).AddOpenEvent(event)

		if settings.DebugLog {
			fmt.Printf("****************\nGot open event from client {ip: %v, port: %v}\n****************\n", utils.ParseIP(event.Addr), utils.ParsePort(event.Addr))
		}
	}
}

func socketCloseEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketCloseEvent
		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}
		event.TimestampNano += settings.GetRealTimeOffset()
		tracker := connectionFactory.Get(event.ConnID)
		if tracker == nil {
			continue
		}
		tracker.AddCloseEvent(event)

		if settings.DebugLog {
			fmt.Println("##############\nGot close event from client\n##############")
		}
	}
}

func main() {
	arg.MustParse(&args)

	settings.DebugLog = args.Verbose

	bpfSourceCodeContent, err := ioutil.ReadFile(args.BPFFile)
	if err != nil {
		log.Panic(err)
	}

	defer privileges.RecoverFromCrashes()
	privileges.AbortIfNotRoot()

	if err := settings.InitRealTimeOffset(); err != nil {
		log.Printf("Failed fixing BPF clock, timings will be offseted: %v", err)
	}

	// Catching all termination signals to perform a cleanup when being stopped.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	bpfModule := bcc.NewModule(string(bpfSourceCodeContent), nil)
	if bpfModule == nil {
		log.Panic("bpf is nil")
	}
	defer bpfModule.Close()

	connectionFactory := connections.NewFactory(time.Minute)
	go func() {
		for {
			connectionFactory.HandleReadyConnections()
			time.Sleep(1 * time.Second)
		}
	}()

	callbacks := make([]*bpfwrapper.ProbeChannel, 0)
	hooks := make([]bpfwrapper.Kprobe, 0)
	if args.Level >= 1 {
		callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_open_events", socketOpenEventCallback))
		hooks = append(hooks, level1hooks...)
	}
	if args.Level >= 2 {
		callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_data_events", socketDataEventCallback))
		hooks = append(hooks, level2hooks...)
	}
	if args.Level >= 3 {
		hooks = append(hooks, level3hooks...)
	}
	if args.Level >= 4 {
		callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_close_events", socketCloseEventCallback))
		hooks = append(hooks, level4hooks...)
	}
	if err := bpfwrapper.LaunchPerfBufferConsumers(bpfModule, connectionFactory, callbacks); err != nil {
		log.Panic(err)
	}

	// Lastly, after everything is ready and configured, attach the kprobes and start capturing traffic.

	if err := bpfwrapper.AttachKprobes(bpfModule, hooks); err != nil {
		log.Panic(err)
	}
	log.Println("Sniffer is ready")
	<-sig
	log.Println("Signaled to terminate")
}
