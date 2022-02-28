package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/alexflint/go-arg"
	"github.com/iovisor/gobpf/bcc"
	"github.com/seek-ret/ebpf-training/workshop5/internal/bpfwrapper"
	"github.com/seek-ret/ebpf-training/workshop5/internal/privileges"
	"github.com/seek-ret/ebpf-training/workshop5/internal/settings"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var (
	hooks = []bpfwrapper.Uprobe{
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_entry_ssl_write",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_ret_ssl_write",
			Type:           bpfwrapper.ReturnType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_entry_ssl_read",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_ret_ssl_read",
			Type:           bpfwrapper.ReturnType,
		},
		{
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_entry_ssl_write",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_ret_ssl_write",
			Type:           bpfwrapper.ReturnType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_entry_ssl_read",
			Type:           bpfwrapper.EntryType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_ret_ssl_read",
			Type:           bpfwrapper.ReturnType,
		},
	}
)

// args represents the command line arguments.
var args struct {
	BPFFile string `arg:"required,positional"`
	PID     int    `arg:"--pid" default:"-1"`
}

// DataEvent is a conversion of the following C-Struct into GO.
//	struct data_event_t {
//		uint64_t timestamp_ns;
//		uint32_t pid;
//		enum traffic_direction_t direction;
//		char msg [400];
//	};
type DataEvent struct {
	TimestampNano uint64
	PID           uint32
	Direction     int32
	Buffer        [400]byte
}

func openEventCallback(inputChan chan []byte) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event DataEvent

		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}

		event.TimestampNano += settings.GetRealTimeOffset()
		if event.Direction == 0 { // egress
			fmt.Printf("****************\nGot egress traffic {pid: %v, time: %v, buffer: %s}\n****************\n", event.PID, time.Unix(0, int64(event.TimestampNano)), string(event.Buffer[:]))
		} else {
			fmt.Printf("****************\nGot ingress traffic {pid: %v, time: %v, buffer: %s}\n****************\n", event.PID, time.Unix(0, int64(event.TimestampNano)), string(event.Buffer[:]))
		}
	}
}

var (
	numberOfCPUs = runtime.NumCPU()
)

func fillPerCPUArray(bpfModule *bcc.Module, arrayName string, key int, value int) error {
	arr := make([]int, numberOfCPUs)
	for i := 0; i < numberOfCPUs; i++ {
		arr[i] = value
	}

	controlValues := bcc.NewTable(bpfModule.TableId(arrayName), bpfModule)
	return controlValues.SetP(unsafe.Pointer(&key), unsafe.Pointer(&arr[0]))
}

func main() {
	arg.MustParse(&args)

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

	callbacks := []*bpfwrapper.ProbeChannel{bpfwrapper.NewProbeChannel("data_events", openEventCallback)}

	if err := bpfwrapper.LaunchPerfBufferConsumers(bpfModule, callbacks); err != nil {
		log.Panic(err)
	}

	if err := fillPerCPUArray(bpfModule, "pid", 0, args.PID); err != nil {
		log.Panic(err)
	}

	if err := bpfwrapper.AttachUprobes("/usr/lib/x86_64-linux-gnu/libssl.so.1.1", args.PID, bpfModule, hooks); err != nil {
		log.Panic(err)
	}
	log.Println("Watcher is ready")
	<-sig
	log.Println("Signaled to terminate")
}
