// Copyright 2016 ETH Zurich
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

package util

import (
	"io"

	"github.com/scionproto/scion/go/lib/common"
)

var _ io.ReadWriter = (*Raw)(nil)

type Raw struct {
	B      common.RawBytes
	Offset int
}

func (r *Raw) Peek(p []byte) (int, error) {
	if len(r.B[r.Offset:]) <= 0 {
		return 0, io.EOF
	}
	return copy(p, r.B[r.Offset:]), nil
}

func (r *Raw) Read(p []byte) (int, error) {
	n, err := r.Peek(p)
	if err == nil {
		r.Offset += n
	}
	return n, err
}

func (r *Raw) Write(p []byte) (int, error) {
	if len(r.B[r.Offset:]) == 0 {
		return 0, io.EOF
	}
	count := copy(r.B[r.Offset:], p)
	r.Offset += count
	return count, nil
}
