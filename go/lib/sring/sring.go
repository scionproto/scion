// Package sring (Slice Ring) implements a simple RingBuffer where the elements
// are slice references.
//
// New allocates buffers internally.
//
// Writers gain exclusive access to the buffers by calling Reserve, and send
// out the buffers after processing by calling Write.
//
// Readers gain exclusive access to the buffers by calling Read.  After
// processing the buffers are marked as available again by calling Release.
package pring

import (
	"fmt"
	"sync"
)

type SRing struct {
	buffers      [][]byte
	reserveIndex int
	writeIndex   int
	readIndex    int
	releaseIndex int

	mutex       sync.Mutex
	readableC   *sync.Cond
	reservableC *sync.Cond

	reservable int
	writable   int
	readable   int
	releasable int
}

// New creates a new SRing with count pre-allocated internal buffers of size
// bytes.
func New(count int, size int) *SRing {
	r := &SRing{}
	r.readableC = sync.NewCond(&r.mutex)
	r.reservableC = sync.NewCond(&r.mutex)
	r.buffers = make([][]byte, count)
	for i := 0; i < count; i++ {
		r.buffers[i] = make([]byte, size)
	}
	r.reservable = count
	return r
}

// Reserve fills buffers with references to pre-allocated slices. The caller
// is assumed to have exclusive access over the returned slices. If no
// reference is available to reserve, the function blocks.
func (r *SRing) Reserve(buffers [][]byte) (int, error) {
	r.mutex.Lock()
	for r.reservable == 0 {
		r.reservableC.Wait()
	}
	// Only reserve what we have available
	n := min(r.reservable, len(buffers))
	r.reserve(buffers[:n])
	r.reservable -= n
	r.writable += n
	r.mutex.Unlock()
	return n, nil
}

// Write copies the buffer references in buffers to the internal ring buffer.
// Writing back more references than are currently reserved returns an error,
// and no operation is performed. On no error, all buffer references are
// guaranteed to be copied. After writing back a buffer reference, callers
// should no longer read or write to it. Write never blocks.
func (r *SRing) Write(buffers [][]byte) (int, error) {
	r.mutex.Lock()
	if len(buffers) > r.writable {
		return 0, fmt.Errorf("Corrupted SRing, insufficient space"+
			"forever (max %d, have %d)", len(r.buffers), buffers)
	}
	r.write(buffers)
	r.writable -= len(buffers)
	r.readable += len(buffers)
	r.readableC.Signal()
	r.mutex.Unlock()
	return len(buffers), nil
}

// Read copies to buffers up to len(buffers) references from the internal ring
// buffer.  The number of copied references is returned. If no element is
// available in the ring buffer, the function blocks.
func (r *SRing) Read(buffers [][]byte) (int, error) {
	r.mutex.Lock()
	for r.readable == 0 {
		r.readableC.Wait()
	}
	n := min(r.readable, len(buffers))
	// Only read what we have available
	r.read(buffers[:n])
	r.readable -= n
	r.releasable += n
	r.mutex.Unlock()
	return n, nil
}

// Release returns the buffer references in buffers back to the ring buffer.
// Attempting to Release more buffers than were Read returns an error, and no
// operation is performed. On no error, all buffer references are guaranteed to
// be released. After releasing a buffer reference, callers should no longer
// read or write to it. Release never blocks.
func (r *SRing) Release(buffers [][]byte) (int, error) {
	r.mutex.Lock()
	if len(buffers) > r.releasable {
		return 0, fmt.Errorf("Corrupted SRing, releasing more buffers"+
			"than read (read %d, releasing %d)", r.releasable,
			len(buffers))
	}
	r.release(buffers)
	r.releasable -= len(buffers)
	r.reservable += len(buffers)
	r.reservableC.Signal()
	r.mutex.Unlock()
	return len(buffers), nil
}

func (r *SRing) reserve(buffers [][]byte) {
	n := copy(buffers, r.buffers[r.reserveIndex:])
	r.reserveIndex += n
	// Wraparound if we need to return more slice references
	if n < len(buffers) {
		// Reset reserve index
		n = copy(buffers[n:], r.buffers)
		r.reserveIndex = n
	}
}

func (r *SRing) write(buffers [][]byte) {
	n := copy(r.buffers[r.writeIndex:], buffers)
	r.writeIndex += n
	// Wraparound if we need to write more slice references
	if n < len(buffers) {
		n = copy(r.buffers, buffers[n:])
		// Reset write index
		r.writeIndex = n
	}
}

func (r *SRing) read(buffers [][]byte) {
	n := copy(buffers, r.buffers[r.readIndex:])
	r.readIndex += n
	// Wraparound if we need to read more slice references
	if n < len(buffers) {
		n = copy(buffers[n:], r.buffers)
		// Reset read index
		r.readIndex = n
	}
}

func (r *SRing) release(buffers [][]byte) {
	n := copy(r.buffers[r.releaseIndex:], buffers)
	r.reserveIndex += n
	// Wraparound if we need to release more slice references
	if n < len(buffers) {
		n = copy(r.buffers, buffers[n:])
		r.releaseIndex = n
	}
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
