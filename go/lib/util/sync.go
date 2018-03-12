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

package util

// ChannelLock implements a sync.Mutex-like API that uses a 1-value channel
// behind the scenes. This makes it usable in selects that also need to meet
// context deadlines.
type ChannelLock struct {
	ch chan struct{}
}

func NewChannelLock() *ChannelLock {
	ch := make(chan struct{}, 1)
	ch <- struct{}{}
	return &ChannelLock{
		ch: ch,
	}
}

// Lock returns a channel that can be drained to acquire the lock.
func (l *ChannelLock) Lock() <-chan struct{} {
	return l.ch
}

func (l *ChannelLock) Unlock() {
	select {
	case l.ch <- struct{}{}:
	default:
		// Programming error, double unlock
		panic("double unlock")
	}
}
