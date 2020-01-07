// Copyright 2019 Anapaya Systems
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

package beaconing

import (
	"time"
)

// tick keeps track whether the period has passed compared to the last time.
type tick struct {
	now    time.Time
	last   time.Time
	period time.Duration
}

// updateLast updates the last time to the current time, if the period has
// passed since last.
func (t *tick) updateLast() {
	if t.passed() {
		t.last = t.now
	}
}

// passed returns whether the last timestamp is further away from now than the period
func (t *tick) passed() bool {
	return t.now.Sub(t.last) >= t.period
}
