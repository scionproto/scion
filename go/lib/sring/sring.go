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

import "github.com/netsec-ethz/scion/go/lib/common"

type SRing struct {
	freeRefs, dataRefs *rb
}

// New creates a new SRing of size count. It pre-allocates internal entries by
// calling newf for each entry.
func New(count int, newf NewEntryF) *SRing {
	r := &SRing{}
	r.freeRefs = newRB(count, newf)
	r.dataRefs = newRB(count, nil)
	return r
}

// Reserve fills entries with pre-allocated entries from the free ring buffer.
// The caller is assumed to have exclusive access over the returned entries. If
// no entries are available to reserve, the function blocks.
func (r *SRing) Reserve(entries EntryList) int {
	return r.freeRefs.Read(entries)
}

// Write copies entries to the data ring buffer and returns the number of
// entries copied. Attempting to write back more entries than can fit into the
// data ring buffer returns an error, and no operation is performed. On
// success, all references are guaranteed to be copied. After writing back an
// entry, callers should no longer read or write to it. Write never blocks.
func (r *SRing) Write(entries EntryList) (int, error) {
	n, max, ok := r.dataRefs.Write(entries)
	if !ok {
		return 0, common.NewError("Attempted to write more entries than reserved",
			"expect", max, "actual", len(entries))
	}
	return n, nil
}

// Read copies up to len(entries) from the data ring buffer to entries, and
// returns the number of copied entries. If no entries are available in the
// data ring buffer, the function blocks.
func (r *SRing) Read(entries EntryList) int {
	return r.dataRefs.Read(entries)
}

// Release returns entries to the free ring buffer and returns the number of
// entries returned. Attempting to Release more entries than can fit into the
// free ring buffer returns an error, and no operation is performed. On
// success, all entries are guaranteed to be released. After releasing an
// entry, callers should no longer read or write to it. Release never blocks.
func (r *SRing) Release(entries EntryList) (int, error) {
	n, max, ok := r.freeRefs.Write(entries)
	if !ok {
		return 0, common.NewError("Attempted to release more entries than acquired",
			"expect", max, "actual", len(entries))
	}
	return n, nil
}
