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

package rpt

import (
	"sync"
	"sync/atomic"

	"github.com/scionproto/scion/go/lib/common"
)

// ackTable maps packet IDs to channels. Goroutines waiting for an ACK for a
// packet ID create a channel, store it in the map at that ID and wait for the
// channel to be closed. The background receiving goroutine closes the channel
// when it receives the corresponding ack.
type ackTable sync.Map

func (m *ackTable) Delete(key uint56) {
	(*sync.Map)(m).Delete(key)
}

func (m *ackTable) Load(key uint56) (chan struct{}, bool) {
	value, loaded := (*sync.Map)(m).Load(key)
	if value == nil {
		return nil, loaded
	}
	return value.(chan struct{}), loaded
}

func (m *ackTable) LoadOrStore(key uint56, value chan struct{}) (chan struct{}, bool) {
	newValue, loaded := (*sync.Map)(m).LoadOrStore(key, value)
	if newValue == nil {
		return nil, loaded
	}
	return newValue.(chan struct{}), loaded
}

func (m *ackTable) Range(f func(uint56, chan struct{}) bool) {
	(*sync.Map)(m).Range(func(k, v interface{}) bool {
		return f(k.(uint56), v.(chan struct{}))
	})
}

func (m *ackTable) Store(key uint56, value chan struct{}) {
	(*sync.Map)(m).Store(key, value)
}

// Supports atomic increments and wraps on 7 bytes.
type uint56 uint64

const (
	maxUint56 = (1 << 56) - 1
)

// Inc atomically increments u, and returns the new value.
func (u *uint56) Inc() uint56 {
	for {
		old := atomic.LoadUint64((*uint64)(u))
		new := (old + 1) % (1 << 56)
		swapped := atomic.CompareAndSwapUint64((*uint64)(u), old, new)
		if swapped {
			return uint56(new)
		}
	}
}

// putUint56 writes a to b in network byte order.
func (a uint56) putUint56(b common.RawBytes) {
	common.Order.PutUintN(b, uint64(a), 7)
}

// getUint56 returns the number in b, read in network byte order.
func getUint56(b common.RawBytes) uint56 {
	return uint56(common.Order.UintN(b, 7))
}
