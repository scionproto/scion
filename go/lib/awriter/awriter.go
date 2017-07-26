package awriter

import (
	"io"

	log "github.com/inconshreveable/log15"
	"github.com/scrye/buffers/pring"
)

type AWriter struct {
	pr  *pring.PRing
	buf []byte
	dst io.Writer
}

func NewAWriter(dst io.Writer) *AWriter {
	aw := &AWriter{}
	aw.pr = pring.NewPRing(1 << 18)
	aw.buf = make([]byte, 1<<18)
	aw.dst = dst
	go flusher(aw)
	return aw
}

func (aw *AWriter) Write(b []byte) (int, error) {
	n, err := aw.pr.Write(b)
	return n, err
}

func flusher(aw *AWriter) {
	// FIXME(scrye): this goroutine needs to be cleaned up whenever a Dispatcher
	// connection is reestablished
	for {
		n, err := aw.pr.Read(aw.buf)
		if err != nil {
			log.Error("Async flush unable to read from PRing", "err", err)
		}

		total := 0
		for total < n {
			written, err := aw.dst.Write(aw.buf[total:n])
			if err != nil {
				log.Error("Async flush unable to write", "err", err, "dst", aw.dst)
			}
			total += written
		}

		aw.buf = aw.buf[:cap(aw.buf)]
	}
}
