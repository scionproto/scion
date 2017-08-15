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

package conn

/*
#include <sys/time.h>

int sizeof_int = sizeof(int);
int sizeof_struct_timeval = sizeof(struct timeval);
*/
import "C"

import (
	"time"
	"unsafe"

	"github.com/netsec-ethz/scion/go/lib/common"
)

const (
	SizeOfInt     = C.sizeof_int
	SizeOfTimeVal = C.sizeof_struct_timeval
)

type Timeval C.struct_timeval

func ParseTimeVal(b common.RawBytes) time.Time {
	tv := *(*Timeval)(unsafe.Pointer(&b[0]))
	return time.Unix(int64(tv.tv_sec), int64(tv.tv_usec)*1000)
}
