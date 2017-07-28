package awriter

import (
	"io"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/pring"
)

type AWriter struct {
	pr          *pring.PRing
	buf         []byte
	dst         io.Writer
	termination bool
}

func NewAWriter(dst io.Writer) *AWriter {
	aw := &AWriter{}
	aw.pr = pring.New(1 << 18)
	aw.buf = make([]byte, 1<<18)
	aw.dst = dst
	go flusher(aw)
	return aw
}

func (aw *AWriter) Write(b []byte) (int, error) {
	n, err := aw.pr.Write(b)
	return n, err
}

func (aw *AWriter) Close() error {
	aw.termination = true
	return nil
}

func flusher(aw *AWriter) {
	var err error
	// FIXME(scrye): this goroutine needs to be cleaned up whenever a Dispatcher
	// connection is reestablished
	for {
		n, err := aw.pr.Read(aw.buf)
		if err != nil {
			break
		}

		total := 0
		for total < n {
			written, err := aw.dst.Write(aw.buf[total:n])
			if err != nil {
				break
			}
			total += written
		}
		aw.buf = aw.buf[:cap(aw.buf)]
	}
	if !aw.termination {
		log.Error("AWriter flush terminated abnormally", "err", err)
	}
}
