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

package msg

import (
	"sync"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/snet"
)

// MaxBufSize is the size of a pre-allocated frame buffer.
const MaxBufSize = 2 << 16

// BufPool is a pool of message buffers.
type BufPool struct {
	*sync.Pool
}

func NewBufPool() *BufPool {
	return &BufPool{&sync.Pool{New: func() interface{} { return newBuf() }}}
}

// Get fetches buffer. The caller shall return the buffer when no longer needed.
func (p *BufPool) Get() *Buf {
	msgBuf := p.Pool.Get().(*Buf)
	msgBuf.reset()
	return msgBuf
}

// Put returns the buffer to the buffer pool.
func (p *BufPool) Put(msgBuf *Buf) {
	p.Pool.Put(msgBuf)
}

// Buf is a buffer for raw data and the corresponding snet address.
type Buf struct {
	Raw  common.RawBytes
	Addr *snet.Addr
}

func newBuf() *Buf {
	buf := &Buf{Raw: make(common.RawBytes, MaxBufSize)}
	buf.reset()
	return buf
}

func (mb *Buf) reset() {
	mb.Raw = mb.Raw[:cap(mb.Raw)]
	mb.Addr = nil
}
