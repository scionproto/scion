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

package common

import (
	"encoding/binary"
	"unsafe"
)

var (
	Order       ByteOrderN = newBigEndianN()
	NativeOrder ByteOrderN
	IsBigEndian bool
)

func init() {
	var v uint16 = 0x11FF
	if (*[2]uint8)(unsafe.Pointer(&v))[0] == 0x11 {
		IsBigEndian = true
		NativeOrder = newBigEndianN()
	} else {
		IsBigEndian = false
		NativeOrder = newLittleEndianN()
	}
}

type ByteOrderN interface {
	binary.ByteOrder
	// Width is the size of the unsigned int value in bytes.
	UintN(b []byte, width int) uint64
	// Width is the size of the unsigned int value in bytes.
	PutUintN(b []byte, v uint64, width int)
}

var _ ByteOrderN = bigEndianN{}

// bigEndianN is the big-endian implementation of ByteOrderN
type bigEndianN struct {
	binary.ByteOrder
}

func newBigEndianN() ByteOrderN {
	return bigEndianN{binary.BigEndian}
}

func (be bigEndianN) UintN(b []byte, width int) uint64 {
	_ = b[width-1]
	var v uint64
	for i := 0; i < width; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v
}

func (be bigEndianN) PutUintN(b []byte, v uint64, width int) {
	_ = b[width-1]
	for i := range b[:width] {
		b[width-i-1] = byte(v)
		v = v >> 8
	}
}

var _ ByteOrderN = littleEndianN{}

// littleEndianN is the little-endian implementation of ByteOrderN
type littleEndianN struct {
	binary.ByteOrder
}

func newLittleEndianN() ByteOrderN {
	return littleEndianN{binary.LittleEndian}
}

func (le littleEndianN) UintN(b []byte, width int) uint64 {
	_ = b[width-1]
	var v uint64
	for i := width - 1; i >= 0; i-- {
		v = (v << 8) | uint64(b[i])
	}
	return v
}

func (le littleEndianN) PutUintN(b []byte, v uint64, width int) {
	_ = b[width-1]
	for i := range b[:width] {
		b[i] = byte(v)
		v = v >> 8
	}
}
