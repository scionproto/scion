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

func TestTriggerNow(t *testing.T) {
	log.Info("TestTriggerNow")
	defer log.Info("TestTriggerNow done")
	want := 10

	cnt := make(chan struct{}, 50)
	fn := taskFunc(func(ctx context.Context) {
		cnt <- struct{}{}
	})

	p := 10 * time.Millisecond
	r := Start(fn, p, 3*p)

	done := make(chan struct{})
	go func() {
		select {
		case <-cnt:
		case <-time.After(2 * p):
			t.Fatalf("time out while waiting on first run")
		}
		for i := 0; i < want; i++ {
			r.TriggerRun()
		}
		close(done)
	}()
	xtest.AssertReadReturnsBefore(t, done, time.Second)
	assert.GreaterOrEqual(t, len(cnt), want-1, "Must run %v times within short time", want-1)
}
