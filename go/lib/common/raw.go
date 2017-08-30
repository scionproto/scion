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

package common

import (
	"fmt"
)

var _ Payload = (*RawBytes)(nil)

type RawBytes []byte

func (r RawBytes) String() string {
	return fmt.Sprintf("%x", []byte(r))
}

func (r RawBytes) Len() int {
	return len(r)
}

func (r RawBytes) Copy() (Payload, *Error) {
	return append(RawBytes{}, r...), nil
}

func (r RawBytes) WritePld(b RawBytes) (int, *Error) {
	if len(b) < len(r) {
		return 0, NewError("Insufficient space", "expected",
			len(r), "actual", len(b))
	}
	return copy(b, r), nil
}
