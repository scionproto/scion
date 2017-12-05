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

package libscion

/*
 #cgo CFLAGS: -I../../../c/lib
 #cgo LDFLAGS: -lscion
 #include <stdint.h>
 #include "scion/scion.h"
*/
import "C"

import (
	"unsafe"

	"github.com/scionproto/scion/go/lib/common"
)

func Checksum(srcs ...common.RawBytes) uint16 {
	chkin := C.mk_chk_input(C.int(len(srcs)))
	for _, src := range srcs {
		var sptr *C.uint8_t
		slen := len(src)
		if slen > 0 {
			sptr = (*C.uint8_t)(unsafe.Pointer(&src[0]))
		} else {
			// Handle zero-length chunks (e.g. payload is empty)
			sptr = nil
		}
		C.chk_add_chunk(chkin, sptr, C.int(slen))
	}
	val := uint16(C.ntohs(C.checksum(chkin)))
	C.rm_chk_input(chkin)
	return val
}
