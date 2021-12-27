package settings

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

var (
	realTimeOffset uint64 = 0
)

// InitRealTimeOffset calculates the offset between the real clock and the monotonic clock used in the BPF.
func InitRealTimeOffset() error {
	var monotonicTime, realTime unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonicTime); err != nil {
		return fmt.Errorf("failed getting monotonic clock due to: %v", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realTime); err != nil {
		return fmt.Errorf("failed getting real clock time due to: %v", err)
	}
	realTimeOffset = uint64(time.Second)*(uint64(realTime.Sec)-uint64(monotonicTime.Sec)) + uint64(realTime.Nsec) - uint64(monotonicTime.Nsec)
	return nil
}

// GetRealTimeOffset is a getter for the real-time-offset.
func GetRealTimeOffset() uint64 {
	return realTimeOffset
}
