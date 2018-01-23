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

package trust

import (
	"sync"
)

// eventMap implements a level-triggered synchronization primitive.
//
// Goroutines can block on the channel returned by Wait(key) until the key is
// signalled by a different goroutine:
//   <- Wait("test")
//
// Once signalled, a key remains signalled forever. Future waiters won't block.
//
// It is safe for multiple reader goroutines and/or a single writer goroutine
// to call eventMap's methods concurrently. Two writers signaling the same key
// at the same time might produce a panic.
type eventMap struct {
	events sync.Map
}

func (em *eventMap) Wait(key interface{}) <-chan struct{} {
	// Grab the existing channel if it exists
	if eventC, ok := em.events.Load(key); ok {
		return eventC.(<-chan struct{})
	}
	// No channel found, create a new one and try to store it
	newEventC := make(chan struct{})
	if eventC, ok := em.events.LoadOrStore(key, newEventC); ok {
		// Somebody else saved their channel first, return theirs
		return eventC.(<-chan struct{})
	}
	// newEventC was successfully stored in the map, return it
	return newEventC
}

func (em *eventMap) Signal(key interface{}) {
	// If a channel already exists, close it
	if eventC, ok := em.events.Load(key); ok {
		c := eventC.(chan struct{})
		select {
		case <-c:
			// already closed, nothing to do
		default:
			close(c)
		}
		return
	}
	// Initialize a closed channel and then attempt to store it for future waiters
	newEventC := make(chan struct{})
	close(newEventC)
	if eventC, ok := em.events.LoadOrStore(key, newEventC); ok {
		// A waiter saved to events map first, close their channel
		close(eventC.(chan struct{}))
	} else {
		// Nothing to do, newEventC is now in the map and closed; future waiters won't block
	}
}
