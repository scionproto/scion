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

func TestKillExitsLongRunningFunc(t *testing.T) {
	log.Info("TestKillExitsLongRunningFunc")
	defer log.Info("TestKillExitsLongRunningFunc done")
	done, errChan := make(chan struct{}), make(chan error, 1)
	p := 10 * time.Millisecond
	fn := taskFunc(func(ctx context.Context) {
		close(done)
		select { // Simulate long work by blocking on the done channel.
		case <-ctx.Done():
			// Happy path r.Kill() cancels context
		case <-time.After(4 * p):
			t.Fatalf("goroutine took too long to finish")
		}
		errChan <- ctx.Err()
	})
	r := Start(fn, p, time.Hour)
	xtest.AssertReadReturnsBefore(t, done, time.Second)
	r.Kill()

	select {
	case err := <-errChan:
		assert.Equal(t, context.Canceled, err, "Context should have been canceled")
	case <-time.After(5 * p):
		t.Fatalf("time out while waiting on err")
	}
}
