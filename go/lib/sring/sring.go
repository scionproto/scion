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

// Package sring (Slice Ring) implements a simple RingBuffer of interface{}
// entries. SRing is organized internally as two ring buffers, one containing
// entries with free space and one containing entries with data.
//
// New allocates entries internally.
//
// Writers gain exclusive access to free entries by calling Reserve, and submit
// the filled entries using Write. Writers can also choose to give back
// unneeded entries directly by calling Release.
//
// Readers gain exclusive access to data entries by calling Read. After
// processing the entries are marked as available again by calling Release. It
// is also valid for a reader to give up ownership by calling Write, although
// this is probably never useful.
//
// Note: SRing never modifies the entries itself, so any required resetting etc
// must be done by the caller(s).
//
// If Write or Release ever attempt to relinquish more entries than would fit
// into the ring buffers, an error is returned and no operation is performed.
// This is generally caused by a logic error in the caller.
package sring

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/common"
)

type SRing struct {
	freeRefs, dataRefs *rb
	metrics            *sringMetrics
}

// New creates a new SRing of size count. It pre-allocates internal entries by
// calling newf for each entry.
func New(count int, newf NewEntryF, desc string, labels prometheus.Labels) *SRing {
	r := &SRing{}
	r.freeRefs = newRB(count, newf)
	r.dataRefs = newRB(count, nil)
	r.metrics = newSRingMetrics(desc, labels)
	return r
}

// Reserve fills entries with pre-allocated entries from the free ring buffer.
// The caller is assumed to have exclusive access over the returned entries. If
// no entries are available to reserve, the function blocks.
func (r *SRing) Reserve(entries EntryList) int {
	r.metrics.resvCalls.Inc()
	n := r.freeRefs.Read(entries)
	r.metrics.resvEntries.Add(float64(n))
	return n
}

// Write copies entries to the data ring buffer and returns the number of
// entries copied. Attempting to write back more entries than can fit into the
// data ring buffer returns an error, and no operation is performed. On
// success, all references are guaranteed to be copied. After writing back an
// entry, callers should no longer read or write to it. Write never blocks.
func (r *SRing) Write(entries EntryList) (int, error) {
	r.metrics.writeCalls.Inc()
	n, max, ok := r.dataRefs.Write(entries)
	if !ok {
		return 0, common.NewCError("Attempted to write more entries than reserved",
			"expect", max, "actual", len(entries))
	}
	r.metrics.writeEntries.Add(float64(n))
	return n, nil
}

// Read copies up to len(entries) from the data ring buffer to entries, and
// returns the number of copied entries. If no entries are available in the
// data ring buffer, the function blocks.
func (r *SRing) Read(entries EntryList) int {
	r.metrics.readCalls.Inc()
	n := r.dataRefs.Read(entries)
	r.metrics.readEntries.Add(float64(n))
	return n
}

// Release returns entries to the free ring buffer and returns the number of
// entries returned. Attempting to Release more entries than can fit into the
// free ring buffer returns an error, and no operation is performed. On
// success, all entries are guaranteed to be released. After releasing an
// entry, callers should no longer read or write to it. Release never blocks.
func (r *SRing) Release(entries EntryList) (int, error) {
	r.metrics.relCalls.Inc()
	n, max, ok := r.freeRefs.Write(entries)
	if !ok {
		return 0, common.NewCError("Attempted to release more entries than acquired",
			"expect", max, "actual", len(entries))
	}
	r.metrics.relEntries.Add(float64(n))
	return n, nil
}
