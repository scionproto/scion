// Copyright 2018 ETH Zurich
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

package snetproxy

import (
	"sync"
)

type AtomicBool struct {
	m sync.Mutex
	v bool
}

func (f *AtomicBool) Set(v bool) {
	f.m.Lock()
	f.v = v
	f.m.Unlock()
}

func (f *AtomicBool) IsTrue() bool {
	f.m.Lock()
	result := f.v == true
	f.m.Unlock()
	return result
}

func (f *AtomicBool) IsFalse() bool {
	return !f.IsTrue()
}

// A State objects encodes an up or down state in a way that can be used
// directly in selects. Note that not all methods are safe for concurrent use
// (see their documentation for more information).
type State struct {
	ch chan struct{}
}

// NewState returns a new state. The state is initially set to up.
func NewState() *State {
	s := &State{ch: make(chan struct{})}
	s.SetUp()
	return s
}

// SetDown sets the state to down.
//
// It is not safe to call SetDown concurrently with other methods.
func (s *State) SetDown() {
	s.ch = make(chan struct{})
}

// SetUp sets the state to up.
//
// It is safe to call SetUp concurrently with Up.
func (s *State) SetUp() {
	close(s.ch)
}

// Up yields a channel that will be closed once SetUp() is called.
//
// It is safe to call SetUp concurrently with Up.
func (s *State) Up() <-chan struct{} {
	return s.ch
}
