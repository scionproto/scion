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
	"reflect"
)

const (
	// LineLen is the number of bytes that all SCION headers are padded to a multiple of.
	LineLen = 8
	MinMTU  = 1280
	MaxMTU  = (1 << 16) - 1
	TimeFmt = "2006-01-02 15:04:05.000000-0700"
)

const (
	BR = "br"
	BS = "bs"
	PS = "ps"
	CS = "cs"
	SB = "sb"
	RS = "rs"
	DS = "ds"
)

// Interface ID
type IFIDType uint64

const IFIDBytes = 8

func TypeOf(v interface{}) string {
	return reflect.TypeOf(v).String()
}
