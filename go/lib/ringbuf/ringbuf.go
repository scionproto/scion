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

package ringbuf

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

type Entry interface{}
type EntryList []Entry
type NewEntryF func() interface{}

// Ring is a classic generic ring buffer on top of a fixed-sized slice. It is thread-safe.
type Ring struct {
	mutex      sync.Mutex
	writableC  *sync.Cond
	readableC  *sync.Cond
	entries    EntryList
	writeIndex int
	readIndex  int
	writable   int
	readable   int
	closed     bool
	metrics    *metrics
}

// New allocates a new Ring instance, with capacity for count entries. If newf
// is non-nil, it is called count times to pre-allocate the entries. labels
// are attached to the prometheus metrics, and desc is added as an extra label.
// N.B. InitMetrics must be called before the first New call.
func New(count int, newf NewEntryF, desc string, labels prometheus.Labels) *Ring {
	r := &Ring{}
	r.writableC = sync.NewCond(&r.mutex)
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
	r.closed = false
	r.metrics = newMetrics(desc, labels)
	r.metrics.maxEntries.Set(float64(count))
	r.metrics.usedEntries.Set(float64(r.readable))
	return r
}

// Write copies entries to the internal ring buffer. If block is true, then
// Write will block until it is able to write at least one entry (or the Ring
// is closed). Otherwise it will return immediately if there's on space left
// for writing.
// In case entries is of length zero, the call returns immediately.
// Returns the number of entries written, or -1 if the RingBuf is closed, and a
// bool indicating if the write blocked.
func (r *Ring) Write(entries EntryList, block bool) (int, bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var blocked bool
	r.metrics.writeCalls.Inc()
	if len(entries) > 0 && r.writable == 0 && !r.closed {
		if !block {
			return 0, blocked
		}
		r.metrics.writesBlocked.Inc()
		for r.writable == 0 && !r.closed {
			blocked = true
			r.writableC.Wait()
		}
	}
	if r.closed {
		return -1, blocked
	}
	n := min(r.writable, len(entries))
	r.write(entries[:n])
	r.writable -= n
	r.readable += n
	r.readableC.Broadcast()
	r.metrics.writeEntries.Observe(float64(n))
	r.metrics.usedEntries.Set(float64(r.readable))
	return n, blocked
}

// Read copies entries from the internal ring buffer. If block is true, then
// Read will block until it is able to read at least one entry (or the Ring
// is closed). Otherwise it will return immediately if there's no entries
// available for reading.
// In case entries is of length zero, the call returns immediately.
// Returns the number of entries read, or -1 if the RingBuf is closed, and a
// bool indicating if the read blocked.
func (r *Ring) Read(entries EntryList, block bool) (int, bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var blocked bool
	r.metrics.readCalls.Inc()
	if len(entries) > 0 && r.readable == 0 && !r.closed {
		if !block {
			return 0, blocked
		}
		r.metrics.readsBlocked.Inc()
		for r.readable == 0 && !r.closed {
			blocked = true
			r.readableC.Wait()
		}
	}
	if r.closed && r.readable == 0 {
		// Don't return -1 so long as there are still readable entries
		// available.
		return -1, blocked
	}
	n := min(r.readable, len(entries))
	r.read(entries[:n])
	r.readable -= n
	r.writable += n
	r.writableC.Broadcast()
	r.metrics.readEntries.Observe(float64(n))
	r.metrics.usedEntries.Set(float64(r.readable))
	return n, blocked
}

// Close closes the ring buffer, and causes all blocked readers/writers to be
// notified.
func (r *Ring) Close() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.closed = true
	r.writableC.Broadcast()
	r.readableC.Broadcast()
}

func (r *Ring) write(entries EntryList) {
	n := copy(r.entries[r.writeIndex:], entries)
	r.writeIndex += n
	// Wraparound if we need to write more slice references
	if n < len(entries) {
		n = copy(r.entries, entries[n:])
		// Reset write index
		r.writeIndex = n
	}
}

func (r *Ring) read(entries EntryList) {
	n := copy(entries, r.entries[r.readIndex:])
	// Remove references that were just read.
	for i := r.readIndex; i < r.readIndex+n; i++ {
		r.entries[i] = nil
	}
	r.readIndex += n
	// Wraparound if we need to read more slice references
	if n < len(entries) {
		n = copy(entries[n:], r.entries)
		// Remove references that were just read.
		for i := 0; i < n; i++ {
			r.entries[i] = nil
		}
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
