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

// Package buffers contains the Dispatcher's pool of free buffers.
//
// FIXME(scrye): Currently the pool is elastic, but this is not ideal for
// traffic bursts. It should probably be replaced with a fixed-sized list.
package buffers

import (
	"sync"

	"github.com/scionproto/scion/go/lib/common"
)

type Buffer struct {
	b common.RawBytes
}

// Reset returns a slice for the entire backing storage of the buffer.
func (b *Buffer) Reset() common.RawBytes {
	return b.b
}

// newBuffer constructs a fixed-size buffer on top of storage b. newBuffer
// takes ownership of b, and calling code should no longer access it directly
// as data can mutate.
func newBuffer(b common.RawBytes) *Buffer {
	buffer := &Buffer{b: b}
	return buffer
}

var pool = sync.Pool{
	New: func() interface{} {
		return newBuffer(make(common.RawBytes, common.MaxMTU))
	},
}

func Get() *Buffer {
	return pool.Get().(*Buffer)
}

func Put(buffer *Buffer) {
	pool.Put(buffer)
}
