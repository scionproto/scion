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
 #cgo CFLAGS: -I../../../lib
 #cgo LDFLAGS: -lscion
 #include <stdint.h>
 #include "libscion/scion.h"
*/
import "C"

import (
	"unsafe"

	"github.com/netsec-ethz/scion/go/lib/util"
)

func Checksum(srcs ...util.RawBytes) uint16 {
	chkin := C.mk_chk_input(C.int(len(srcs)))
	for _, src := range srcs {
		C.chk_add_chunk(chkin, (*C.uint8_t)(unsafe.Pointer(&src[0])), C.int(len(src)))
	}
	val := uint16(C.ntohs(C.checksum(chkin)))
	C.rm_chk_input(chkin)
	return val
}
