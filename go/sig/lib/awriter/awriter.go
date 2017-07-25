package awriter

import (
	"bufio"
	"io"
	"sync"
)

type AWriter struct {
	dst        *bufio.Writer
	flushCond  *sync.Cond
	flushMutex sync.Mutex
	flushable  bool
}

func NewAWriter(dst io.Writer) *AWriter {
	aw := &AWriter{}
	aw.dst = bufio.NewWriterSize(dst, 1<<18)
	aw.flushCond = sync.NewCond(&aw.flushMutex)
	go flusher(aw)
	return aw
}

func (aw *AWriter) Write(b []byte) (int, error) {
	aw.flushMutex.Lock()
	n, err := aw.dst.Write(b)
	aw.flushable = true
	aw.flushCond.Signal()
	aw.flushMutex.Unlock()
	return n, err
}

func flusher(aw *AWriter) {
	for {
		aw.flushMutex.Lock()
		for aw.flushable == false {
			aw.flushCond.Wait()
		}
		aw.dst.Flush()
		aw.flushable = false
		aw.flushMutex.Unlock()
	}
}
