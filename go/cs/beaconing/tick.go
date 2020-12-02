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

// Tick keeps track whether the period has passed compared to the last time.
//
// If the Tick's clock has never been set, its value is the default Go time.Time.
type Tick struct {
	now    time.Time
	last   time.Time
	period time.Duration
}

func NewTick(period time.Duration) Tick {
	return Tick{period: period}
}

func (t *Tick) SetNow(now time.Time) {
	t.now = now
}

func (t *Tick) Now() time.Time {
	return t.now
}

// Overdue returns true if the Tick's period has elapsed since timestamp in the
// past up to the Tick's Now time.
func (t *Tick) Overdue(timestamp time.Time) bool {
	return t.now.Sub(timestamp) > t.period
}

func (t *Tick) Period() time.Duration {
	return t.period
}

// UpdateLast updates the last time to the current time, if the period has
// passed since last.
func (t *Tick) UpdateLast() {
	if t.Passed() {
		t.last = t.now
	}
}

// Passed returns true if the Tick's period has elapsed since the last UpdateLast call up to
// the Tick's Now time.
func (t *Tick) Passed() bool {
	return t.now.Sub(t.last) >= t.period
}
