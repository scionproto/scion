// Package sring (Slice Ring) implements a simple RingBuffer where the elements
// are slice references.
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
// If Write or Release ever attempts to relinquish more references than would
// fit into the ring buffer, an error is returned and no operation is
// performed. This is generally caused by a logic error in the caller.
package pring

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

// Reserve fills buffers with references to pre-allocated slices. The caller
// is assumed to have exclusive access over the returned slices. If no
// reference is available to reserve, the function blocks.
func (r *SRing) Reserve(buffers [][]byte) int {
	return r.freeRefs.Read(buffers)
}

// Write copies the buffer references in buffers to the internal ring buffer.
// Attempting to write back more references than can fit into the ring buffer
// returns an error, and no operation is performed. On no error, all buffer
// references are guaranteed to be copied. After writing back a buffer
// reference, callers should no longer read or write to it. Write never blocks.
func (r *SRing) Write(buffers [][]byte) (int, error) {
	n, max, ok := r.dataRefs.Write(buffers)
	if !ok {
		return 0, common.NewError("Attempted to write more buffers than reserved",
			"expect", max, "actual", len(buffers))
	}
	return n, nil
}

// Read copies to buffers up to len(buffers) references from the internal ring
// buffer.  The number of copied references is returned. If no element is
// available in the ring buffer, the function blocks.
func (r *SRing) Read(buffers [][]byte) int {
	return r.dataRefs.Read(buffers)
}

// Release returns the buffer references in buffers back to the ring buffer.
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
