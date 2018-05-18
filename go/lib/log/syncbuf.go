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

package log

import (
	"bufio"
	"io"
	"sync"
)

var _ io.WriteCloser = (*syncBuf)(nil)

type syncBuf struct {
	sync.Mutex
	wr  io.WriteCloser
	buf *bufio.Writer
}

func newSyncBuf(w io.WriteCloser) *syncBuf {
	return &syncBuf{wr: w, buf: bufio.NewWriterSize(w, 1<<16)}
}

func (s *syncBuf) Write(b []byte) (int, error) {
	s.Lock()
	defer s.Unlock()
	return s.buf.Write(b)
}

func (s *syncBuf) Flush() error {
	s.Lock()
	defer s.Unlock()
	return s.buf.Flush()
}

func (s *syncBuf) Close() error {
	s.Lock()
	defer s.Unlock()
	s.buf.Flush()
	return s.wr.Close()
}
