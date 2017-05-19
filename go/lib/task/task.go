// Copyright 2017 ETH Zurich
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

package task

import (
	"sync"

	"github.com/netsec-ethz/scion/go/lib/common"
)

// StopFunc is a function that returns true if the goroutine should stop executing.
type StopFunc func() bool

// Run executes the function in a goroutine and returns a Task to stop the execution.
func Run(fn func(StopFunc) *common.Error) *Task {
	t := &Task{
		StopChan: make(chan struct{}),
		running:  true,
	}
	go func() {
		err := fn(func() bool {
			t.RLock()
			defer t.RUnlock()
			return t.shouldStop
		})
		t.Lock()
		t.err = err
		t.running = false
		close(t.StopChan)
		t.Unlock()
	}()
	return t
}

// Task represents an interruptable goroutine.
type Task struct {
	sync.RWMutex
	StopChan   chan struct{}
	shouldStop bool
	running    bool
	err        *common.Error
}

// Stop tells the goroutine to stop.
func (t *Task) Stop() {
	t.Lock()
	t.shouldStop = true
	t.Unlock()
}

// Running gets whether the goroutine is running or not.
func (t *Task) Running() bool {
	t.RLock()
	defer t.RUnlock()
	return t.running
}

// Err gets the error returned by the goroutine.
func (t *Task) Err() error {
	t.RLock()
	defer t.RUnlock()
	return t.err
}
