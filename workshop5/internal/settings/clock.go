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
