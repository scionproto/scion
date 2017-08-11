// Package sring (Slice Ring) implements a simple RingBuffer where the elements
// are slice references. SRing is organized internally as two ring buffers,
// one containing slices with free space and one containing slices with data.
//
// New allocates buffers internally.
//
// Writers gain exclusive access to the buffers by calling Reserve, and send
// out the buffers after processing by calling Write. Writers can also choose
// to free the buffers directly by calling Release.
//
// Readers gain exclusive access to the buffers by calling Read. After
// processing the buffers are marked as available again by calling Release. It
// is also valid for a reader to give up ownership by calling Write, although
// this is probably never useful.
//
// Slice capacity is never reset internally, this has to be done by the caller.
//
// If Write or Release ever attempts to relinquish more references than would
// fit into the ring buffer, an error is returned and no operation is
// performed. This is generally caused by a logic error in the caller.
package sring

import "github.com/netsec-ethz/scion/go/lib/common"

type SRing struct {
	freeRefs, dataRefs *rb
}

// New creates a new SRing with count pre-allocated internal buffers of size
// bytes.
func New(count int, size int) *SRing {
	r := &SRing{}
	r.freeRefs = newRB(count, size)
	r.dataRefs = newRB(count, 0)
	return r
}

// Reserve copies slice references from the free ring buffer to buffers.
// The caller is assumed to have exclusive access over the returned slices. If
// no slice is available to reserve, the function blocks.
func (r *SRing) Reserve(buffers [][]byte) int {
	return r.freeRefs.Read(buffers)
}

// Write copies the slice references in buffers to the data ring buffer.
// Attempting to write back more references than can fit into the ring buffer
// returns an error, and no operation is performed. On no error, all references
// are guaranteed to be copied. After writing back a reference, callers should
// no longer read or write to it. Write never blocks.
func (r *SRing) Write(buffers [][]byte) (int, error) {
	n, max, ok := r.dataRefs.Write(buffers)
	if !ok {
		return 0, common.NewError("Attempted to write more buffers than reserved",
			"expect", max, "actual", len(buffers))
	}
	return n, nil
}

// Read copies slice references from the data ring buffer to buffers.  The
// number of copied references is returned; this can be anywhere from 1 to
// len(buffers), depending on available data. If no element is available in the
// ring buffer, the function blocks.
func (r *SRing) Read(buffers [][]byte) int {
	return r.dataRefs.Read(buffers)
}

// Release copies the slice references in buffers to the free ring buffer.
// Attempting to Release more buffers than can fit into the ring buffer returns
// an error, and no operation is performed. On no error, all buffer references
// are guaranteed to be released. After releasing a buffer reference, callers
// should no longer read or write to it. Release never blocks.
func (r *SRing) Release(buffers [][]byte) (int, error) {
	n, max, ok := r.freeRefs.Write(buffers)
	if !ok {
		return 0, common.NewError("Attempted to release more buffers than acquired",
			"expect", max, "actual", len(buffers))
	}
	return n, nil
}
