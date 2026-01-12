// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package priority

import (
	"reflect"
)

type PriorityLabel uint8

const (
	WithPriority PriorityLabel = iota
	WithBestEffort
	lastPriority

	QueueCount = int(lastPriority)
)

type Queue[T any] [QueueCount]<-chan T

// ReadAsync returns a value from the queues read in their priority order.
// If no value is available, this function does not block and returns false.
func ReadAsync[T any](queue Queue[T]) (T, bool) {
	var v T
	var ok bool
loop:
	for _, q := range queue {
		select {
		case v, ok = <-q:
			if !ok {
				// Channel is closed.
				continue
			}
			break loop
		default:
		}
	}
	return v, ok
}

// ReadBlocking returns the first available value from the queues, retrieved in priority order.
// If no value is available at any queue, it blocks until one queue receives a value.
// It returns the value, and a boolean indicating whether all channels are closed.
// XXX(juagargi) In Go, there isn't a general method to synchronously read a value from multiple
// channels. There exists reflect.Select, but it's expensive (see unexported functions below).
// Instead, we
func ReadBlocking[T any](queue Queue[T]) (T, bool) {
	// Compile guards because we have manual code below that is written only for the
	// case of two queues (channels) in the Queue definition.
	var _ [2 - len(queue)]int // assert( len(queue) <= 2 )
	var _ [len(queue) - 2]int // assert( len(queue) >= 2 )

	v, ok := ReadAsync(queue)
	if ok {
		// We got a value we can return.
		return v, ok
	}
	// Block until any queue has a value.
	select {
	case v, ok := <-queue[0]:
		return v, ok
	case v, ok := <-queue[1]:
		return v, ok
	}
}

// The following functions are left here only for reference and to test the performance of the
// methods based on reflect logic. They are not exported and not used outside the benchmarks.

func readBlockingReflect[T any](queue Queue[T]) (T, bool) {
	cases := []reflect.SelectCase{}
	for i := range queue {
		c := reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(queue[i]),
		}
		cases = append(cases, c)
	}
	chosenCase, v, ok := reflect.Select(cases)
	_ = chosenCase
	vv := v.Interface().(T)
	return vv, ok
}

type reflectWrapper[T any] struct {
	queue       Queue[T]
	selectCases []reflect.SelectCase
}

func newReflectWrapper[T any](queue Queue[T]) *reflectWrapper[T] {
	cases := []reflect.SelectCase{}
	for i := range queue {
		c := reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(queue[i]),
		}
		cases = append(cases, c)
	}
	return &reflectWrapper[T]{
		queue:       queue,
		selectCases: cases,
	}
}

func (w *reflectWrapper[T]) readBlocking() (T, bool) {
	chosenCase, v, ok := reflect.Select(w.selectCases)
	_ = chosenCase
	vv := v.Interface().(T)
	return vv, ok
}
