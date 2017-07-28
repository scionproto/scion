// Package pring (Packet Ring) implements a simple RingBuffer for framed data.
// Partial writes are not allowed; if there is not enough space for the data
// the call to Write will block. Read always reads the entire contents of the
// pring structure. If the buffer passed to Read is not big enough to handle
// the available data, an error is returned and no bytes are read.
package pring

import (
	"fmt"
	"sync"
)

// Type PRing (Packet Ring) implements io.Writer and io.Reader over a
// RingBuffer for packet data.
type PRing struct {
	b      []byte
	windex int
	rindex int
	length int

	mutex     sync.Mutex
	writeable *sync.Cond
	readable  *sync.Cond
}

func NewPRing(size int) *PRing {
	r := &PRing{}
	r.writeable = sync.NewCond(&r.mutex)
	r.readable = sync.NewCond(&r.mutex)
	r.b = make([]byte, size)
	return r
}

// Write copies the contents of b to the internal buffer. If there is
// insufficient space to write everything, the call blocks. Everything is
// copied in a single operation, so readers can never get fragments of packets.
func (r *PRing) Write(b []byte) (int, error) {
	if len(b) > len(r.b) {
		return 0, fmt.Errorf("Buffer too large for write, would block"+
			"forever (max %d, have %d)", len(r.b), b)
	}
	r.mutex.Lock()
	for len(b) > r.spaceAvailable() {
		r.writeable.Wait()
	}
	r.write(b)
	r.readable.Signal()
	r.mutex.Unlock()
	return len(b), nil
}

// Read copies all available data to b. If b is not large enough to fit all the
// data, an error is returned and no bytes are copied. Due to the all or
// nothing nature of writes, the copied data is guaranteed to contain only
// complete packets.
func (r *PRing) Read(b []byte) (int, error) {
	if len(b) < r.dataAvailable() {
		return 0, fmt.Errorf("Insufficient read buffer size (want %d, have %d)",
			r.dataAvailable(), len(b))
	}
	r.mutex.Lock()
	for r.dataAvailable() == 0 {
		r.readable.Wait()
	}
	n := r.read(b)
	r.writeable.Signal()
	r.mutex.Unlock()
	return n, nil
}

func (r *PRing) write(b []byte) int {
	copied := copy(r.b[r.windex:], b)
	r.length += copied
	left := len(b) - copied
	if left == 0 {
		r.windex += copied
		return len(b)
	}
	copied = copy(r.b, b[copied:])
	r.windex = copied
	r.length += copied
	return len(b)
}

func (r *PRing) read(b []byte) int {
	oldLength := r.length
	if r.length > len(r.b)-r.rindex {
		// Copy from current reading index until the end
		copied := copy(b, r.b[r.rindex:])
		// Copy remaining bytes from the start
		copied = copy(b[copied:], r.b[:r.length-copied])
		// Reset reading index and length
		r.rindex = copied
		r.length = 0
	} else {
		// Everything before the end, Only one copy needed
		copied := copy(b, r.b[r.rindex:r.rindex+r.length])
		r.length = 0
		r.rindex += copied
	}
	return oldLength
}

func (r *PRing) spaceAvailable() int {
	return len(r.b) - r.length
}

func (r *PRing) dataAvailable() int {
	return r.length
}
