// Copyright 2018 Anapaya Systems
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

package periodic

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestPeriodicExecution(t *testing.T) {
	log.Info("TestPeriodicExecution")
	defer log.Info("TestPeriodicExecution done")
	cnt := make(chan struct{})
	fn := taskFunc(func(ctx context.Context) {
		cnt <- struct{}{}
	})
	want := 5
	p := time.Duration(want) * time.Millisecond
	r := Start(fn, p, time.Hour)
	defer r.Stop()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		v := 0
		for {
			select {
			case <-cnt:
				v++
				if v == want {
					close(done)
					return
				}
			case <-time.After(2 * p):
				t.Fatalf("time out while waiting on first run")
			}
		}
	}()
	xtest.AssertReadReturnsBefore(t, done, time.Second)
	assert.WithinDurationf(t, start, time.Now(), time.Duration(want+2)*p,
		"more or less %d * periods", want+2)
}
