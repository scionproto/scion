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
	"fmt"
)

// XXX(kormat): not 100% sure if this is useful, yet.

type Raw struct {
	data   []byte
	Offset int
}

func NewRaw(data []byte) *Raw {
	return &Raw{data: data}
}

func (r *Raw) Peek(count int) ([]byte, error) {
	if count > (len(r.data) - r.Offset) {
		return nil, fmt.Errorf("Cannot satisfy request")
	}
	return r.data[r.Offset : r.Offset+count], nil
}

func (r *Raw) Pop(count int) ([]byte, error) {
	d, err := r.Peek(count)
	if err != nil {
		return nil, err
	}
	r.Offset += count
	return d, nil
}

type RawBytes []byte

func (r RawBytes) String() string {
	return fmt.Sprintf("%x", []byte(r))
}
