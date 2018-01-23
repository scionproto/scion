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

package sring

import "sync"

type Entry interface{}
type EntryList []Entry
type NewEntryF func() interface{}

// NewEntryBytes is a convenience function to simplify using []byte as the
// entry type for SRing.
func NewEntryBytes(n int) NewEntryF {
	return func() interface{} {
		return make([]byte, n)
	}
}

// rb is a classical ring buffer for slices which throws errors
// whenever a write is larger than the current available space
type rb struct {
	mutex      sync.Mutex
	readableC  *sync.Cond
	entries    EntryList
	writeIndex int
	readIndex  int
	writable   int
	readable   int
}

func newRB(count int, newf NewEntryF) *rb {
	r := &rb{}
	r.readableC = sync.NewCond(&r.mutex)
	r.entries = make(EntryList, count)
	// Only allocate memory if caller requested it
	if newf != nil {
		for i := 0; i < count; i++ {
			r.entries[i] = newf()
		}
		// A ring buffer that allocates data starts off as full
		r.readable = count
	} else {
		// A ring buffer that does not allocate starts off as empty
		r.writable = count
	}
	return r
}

// Write copies entries to the internal ring buffer. Attempting to write more
// than the available space causes Write to fail. Return arguments contain the
// number of written entries (all on success, 0 on failure), the number of
// available spaces (0 on success, actual space on failure) and whether the
// operation succeeded.
func (r *rb) Write(entries EntryList) (int, int, bool) {
	r.mutex.Lock()
	// Attempting to free up more resources than we acquired points to a
	// logic error in the calling code
	if len(entries) > r.writable {
		writable := r.writable
		r.mutex.Unlock()
		return 0, writable, false
	}
	n := min(r.writable, len(entries))
	r.write(entries[:n])
	r.writable -= n
	r.readable += n
	r.readableC.Signal()
	r.mutex.Unlock()
	return n, 0, true
}

func (r *rb) Read(entries EntryList) int {
	r.mutex.Lock()
	for r.readable == 0 {
		r.readableC.Wait()
	}
	n := min(r.readable, len(entries))
	r.read(entries[:n])
	r.readable -= n
	r.writable += n
	r.mutex.Unlock()
	return n
}

func (r *rb) write(entries EntryList) {
	n := copy(r.entries[r.writeIndex:], entries)
	r.writeIndex += n
	// Wraparound if we need to write more slice references
	if n < len(entries) {
		n = copy(r.entries, entries[n:])
		// Reset write index
		r.writeIndex = n
	}
}

func (r *rb) read(entries EntryList) {
	n := copy(entries, r.entries[r.readIndex:])
	r.readIndex += n
	// Wraparound if we need to read more slice references
	if n < len(entries) {
		n = copy(entries[n:], r.entries)
		// Reset read index
		r.readIndex = n
	}
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
