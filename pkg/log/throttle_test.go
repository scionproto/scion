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

package log_test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/log"
)

func TestThrottle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		called := 0
		suppressed := 0
		throttle := log.Throttle{Interval: time.Second}
		for i := 0; i < 100; i++ {
			throttle.Do(func(suppressedCount int) { called++; suppressed = suppressedCount })
		}
		// Initially we expect the function to be called once, and then to be
		// suppressed for the next calls. After sleeping for the interval, we
		// expect it to be called again, and the suppressed count to be greater
		// than 0.
		assert.Equal(t, 1, called)
		assert.Equal(t, 0, suppressed)
		time.Sleep(time.Second + time.Microsecond)
		throttle.Do(func(suppressedCount int) { called++; suppressed = suppressedCount })
		assert.Equal(t, 2, called)
		assert.Equal(t, 99, suppressed)
	})
}
