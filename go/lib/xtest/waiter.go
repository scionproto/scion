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

package xtest

import (
	"sync"
	"time"
)

// Waiter wraps the waitgroup and allows waiting with timeouts.
type Waiter struct {
	sync.WaitGroup
}

// WaitWithTimeout returns immediately after the waitgroup is done,
// or the timeout has passed. The return value indicates whether
// the call timed out.
func (w *Waiter) WaitWithTimeout(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.WaitGroup.Wait()
	}()
	select {
	case <-done:
		return false
	case <-time.After(timeout):
		return true
	}
}
