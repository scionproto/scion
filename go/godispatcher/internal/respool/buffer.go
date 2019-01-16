// Copyright 2018 ETH Zurich
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

// Package respool contains the Dispatcher's pool of free buffers/packets.
//
// FIXME(scrye): Currently the pools are elastic, but this is not ideal for
// traffic bursts. Consider converting these to fixed-size lists.
package respool

import (
	"sync"

	"github.com/scionproto/scion/go/lib/common"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make(common.RawBytes, common.MaxMTU)
	},
}

func GetBuffer() common.RawBytes {
	b := bufferPool.Get().(common.RawBytes)
	return b[:cap(b)]
}

func PutBuffer(b common.RawBytes) {
	if cap(b) == common.MaxMTU {
		bufferPool.Put(b)
	}
}
