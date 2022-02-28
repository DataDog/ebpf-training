package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/alexflint/go-arg"
	"github.com/iovisor/gobpf/bcc"
	"github.com/seek-ret/ebpf-training/workshop4/internal/bpfwrapper"
	"github.com/seek-ret/ebpf-training/workshop4/internal/privileges"
	"github.com/seek-ret/ebpf-training/workshop4/internal/settings"
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
	level1hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "openat",
			HookName:       "syscall__probe_entry_openat",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "openat",
			HookName:       "syscall__probe_ret_openat",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}
	level2hooks = []bpfwrapper.Kprobe{
		{
			FunctionToHook: "openat",
			HookName:       "syscall__probe_entry_openat",
			Type:           bpfwrapper.EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "openat",
			HookName:       "syscall__probe_ret_openat_deny",
			Type:           bpfwrapper.ReturnType,
			IsSyscall:      true,
		},
	}
)

// args represents the command line arguments.
var args struct {
	BPFFile   string `arg:"required,positional"`
	Level     int    `arg:"--level,required"`
	Level2PID int    `arg:"--level2-pid" default:"-1"`
}

// OpenEvent is a conversion of the following C-Struct into GO.
//	struct open_event_t {
//		uint64_t timestamp_ns;
//		pid uint32_t;
// 		int return_code;
//		char copiedPath [255];
// 	};
type OpenEvent struct {
	TimestampNano uint64
	PID           uint32
	ReturnCode    int32
	EventType     int32
	Buffer        [255]byte
}

func openEventCallback(inputChan chan []byte) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event OpenEvent

		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}

		event.TimestampNano += settings.GetRealTimeOffset()
		if event.EventType == 0 {
			fmt.Printf("****************\nGot open event for {path: %v, return code: %v, pid: %v, time: %v}\n****************\n", string(event.Buffer[:]), event.ReturnCode, event.PID, time.Unix(0, int64(event.TimestampNano)))
		} else {
			fmt.Printf("****************\nDenied access for {path: %v, pid: %v, time: %v}\n****************\n", string(event.Buffer[:]), event.PID, time.Unix(0, int64(event.TimestampNano)))
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

	callbacks := make([]*bpfwrapper.ProbeChannel, 0)
	hooks := make([]bpfwrapper.Kprobe, 0)
	if args.Level == 1 {
		callbacks = append(callbacks, bpfwrapper.NewProbeChannel("open_events", openEventCallback))
		hooks = append(hooks, level1hooks...)
	} else if args.Level == 2 {
		if args.Level2PID == -1 {
			log.Panic("Must supply level 2 PID flag")
		}
		if err := fillPerCPUArray(bpfModule, "pid", 0, args.Level2PID); err != nil {
			log.Panic(err)
		}
		callbacks = append(callbacks, bpfwrapper.NewProbeChannel("open_events", openEventCallback))
		hooks = append(hooks, level2hooks...)
	}

	if err := bpfwrapper.LaunchPerfBufferConsumers(bpfModule, callbacks); err != nil {
		log.Panic(err)
	}

	if err := bpfwrapper.AttachKprobes(bpfModule, hooks); err != nil {
		log.Panic(err)
	}
	log.Println("Watcher is ready")
	<-sig
	log.Println("Signaled to terminate")
}
