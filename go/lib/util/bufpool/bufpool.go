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

// Package bufpool initializes an elastic pool of free buffers. Buffer have capacity
// common.MaxMTU.
//
// Apps can use bufpool to ammortize allocations between multiple goroutines
// without preallocating a large amount of memory. Details about how the
// allocation and freeing of resources works can be found in the documentation
// for sync.Pool.
//
// For apps where the performance penalty of grabbing a single free buffer is
// non-neglibile (e.g., per packet processing in a router), package ringbuf (and
// manual management of free buffers) should be used instead.
package bufpool

import (
	"sync"

	"github.com/scionproto/scion/go/lib/common"
)

var freeList = newFreeListT(common.MaxMTU)

// freeListT is a type-explicit wrapper around sync.Pool for Buffer objects.
type freeListT sync.Pool

func newFreeListT(capacity int) *freeListT {
	pool := &sync.Pool{
		New: func() interface{} {
			return newBuffer(capacity)
		},
	}
	return (*freeListT)(pool)
}

func (list *freeListT) get() *Buffer {
	item := (*sync.Pool)(list).Get()
	return item.(*Buffer)
}

func (list *freeListT) put(buffer *Buffer) {
	buffer.Reset()
	(*sync.Pool)(list).Put(buffer)
}

// Get returns a buffer from the free buffer pool. If a buffer is not
// available, a new one is allocated.
func Get() *Buffer {
	return freeList.get()
}

// Put resets a buffer to its initial length and capacity and returns it to the
// free buffer pool.
func Put(buffer *Buffer) {
	// Prohibit uninitialized buffers from being added to the pool
	if buffer.arena == nil {
		panic("invalid Buffer object")
	}
	// Resetting happens inside put
	freeList.put(buffer)
}

// Buffer is a container for a common.RawBytes object B. B can be safely
// resliced. Calling Reset will return B to its initial length and capacity.
type Buffer struct {
	arena common.RawBytes
	B     common.RawBytes
}

func newBuffer(capacity int) *Buffer {
	arena := make(common.RawBytes, capacity)
	return &Buffer{
		arena: arena,
		B:     arena,
	}
}

// Reset restores b.B to its initial length and capacity.
func (b *Buffer) Reset() {
	b.B = b.arena
}

// CloneB returns a copy of the data in b.B.
func (b *Buffer) CloneB() common.RawBytes {
	return append(common.RawBytes(nil), b.B...)
}
