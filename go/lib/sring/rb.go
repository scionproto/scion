package sring

import "sync"

// rb is a classical ring buffer for slices which throws errors
// whenever a write is larger than the current available space
type rb struct {
	mutex      sync.Mutex
	readableC  *sync.Cond
	buffers    [][]byte
	writeIndex int
	readIndex  int
	writable   int
	readable   int
}

func newRB(count int, size int) *rb {
	r := &rb{}
	r.readableC = sync.NewCond(&r.mutex)
	r.buffers = make([][]byte, count)
	// Only allocate memory if caller requested it
	if size != 0 {
		for i := 0; i < count; i++ {
			r.buffers[i] = make([]byte, size)
		}
		// A ring buffer that allocates data starts off as full
		r.readable = count
	} else {
		// A ring buffer that does not allocate starts off as empty
		r.writable = count
	}
	return r
}

func (r *rb) Write(buffers [][]byte) (int, int, bool) {
	r.mutex.Lock()
	// Attempting to free up more resources than we acquired points to a
	// logic error in the calling code
	if len(buffers) > r.writable {
		writable := r.writable
		r.mutex.Unlock()
		return 0, writable, false
	}
	n := min(r.writable, len(buffers))
	r.write(buffers[:n])
	r.writable -= n
	r.readable += n
	r.readableC.Signal()
	r.mutex.Unlock()
	return n, 0, true
}

func (r *rb) Read(buffers [][]byte) int {
	r.mutex.Lock()
	for r.readable == 0 {
		r.readableC.Wait()
	}
	n := min(r.readable, len(buffers))
	r.read(buffers[:n])
	r.readable -= n
	r.writable += n
	r.mutex.Unlock()
	return n
}

func (r *rb) write(buffers [][]byte) {
	n := copy(r.buffers[r.writeIndex:], buffers)
	r.writeIndex += n
	// Wraparound if we need to write more slice references
	if n < len(buffers) {
		n = copy(r.buffers, buffers[n:])
		// Reset write index
		r.writeIndex = n
	}
}

func (r *rb) read(buffers [][]byte) {
	n := copy(buffers, r.buffers[r.readIndex:])
	r.readIndex += n
	// Wraparound if we need to read more slice references
	if n < len(buffers) {
		n = copy(buffers[n:], r.buffers)
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
