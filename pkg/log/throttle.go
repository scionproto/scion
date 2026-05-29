// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"sync"
	"time"
)

// Throttle provides rate limiting for log messages to prevent log flooding. The
// zero value is ready to use with a default interval of 5 seconds. Use one
// throttle per log message type, and call Do with a function that logs the
// message
type Throttle struct {
	// Interval is the minimum time between log emissions. Defaults to 5 seconds.
	Interval time.Duration

	mu              sync.Mutex
	lastEmitted     time.Time
	suppressedCount int
}

func (lt *Throttle) interval() time.Duration {
	if lt.Interval == 0 {
		return 5 * time.Second
	}
	return lt.Interval
}

// Do calls fn with the number of calls suppressed since the last emission,
// if the throttle interval has elapsed. fn is not called if the interval has
// not yet elapsed.
func (lt *Throttle) Do(fn func(suppressedCount int)) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	now := time.Now()
	if now.Sub(lt.lastEmitted) > lt.interval() {
		fn(lt.suppressedCount)
		lt.lastEmitted = now
		lt.suppressedCount = 0
		return
	}
	lt.suppressedCount++
}
