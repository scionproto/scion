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
)

func cBackedSlice(p *C.uint8_t, length int) []uint8 {
	// Trick to create a Go byte slice backed by the original C char array
	// https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
	return (*[1 << 30]uint8)(unsafe.Pointer(p))[:length:length]
}

func sliceToArray(b []uint8) *C.uint8_t {
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}
