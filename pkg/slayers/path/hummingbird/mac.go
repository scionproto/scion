// Copyright 2025 ETH Zurich
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

//go:build amd64 || arm64 || ppc64 || ppc64le

package hummingbird

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path"
)

// The FullFlyoverMac makes use of the assembly code in the asm_* files
// There are two main, related, reasons for that.
// First, the AES key expansion performed by these assembly files is
// much faster than what the library code does.
// BenchmarkFlyoverMac and BenchmarkFlyoverMacLib in mac_test.go show the difference
//
// Second, the library implementation of the AES key expansion performs calls to make()
// and allocates memory, which we would like to avoid
// This is also the main reason why the direct call to assembly is much faster
//
// A full implementation of AES written in go only without memory allocations
// has been attempted, but turned out to not be much more efficient than
// the library implementation.
// This is expectedt to be due to the fact that a go only implementation of AES
// is unable to make use of hardware accelerated AES instructions.

// defined in asm_* assembly files

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc *uint32)

const (
	PathType = 5

	aesRounds            = 10
	AkBufferSize         = 16
	FlyoverMacBufferSize = 16
	XkBufferSize         = (aesRounds + 1) * (128 / 32) // 44
	// Total MAC buffer size:
	MACBufferSize = path.MACBufferSize + FlyoverMacBufferSize + AkBufferSize
)

// Derive authentication key A_k
// block is expected to be initialized beforehand with aes.NewCipher(sv),
// where sv is this AS' secret value
// Requires buffer to be of size at least AkBufferSize
func DeriveAuthKey(
	block cipher.Block,
	resId uint32,
	bw uint16,
	in uint16,
	eg uint16,
	startTime uint32,
	resDuration uint16,
	buffer []byte,
) []byte {

	// Bounds check.
	_ = buffer[AkBufferSize-1]

	// Prepare input buffer.
	binary.BigEndian.PutUint16(buffer[0:2], in)
	binary.BigEndian.PutUint16(buffer[2:4], eg)
	binary.BigEndian.PutUint32(buffer[4:8], resId<<10|uint32(bw))
	binary.BigEndian.PutUint32(buffer[8:12], startTime)
	binary.BigEndian.PutUint16(buffer[12:14], resDuration)
	binary.BigEndian.PutUint16(buffer[14:16], 0) //padding

	// Should XOR input with iv, but we use iv = 0 => identity
	block.Encrypt(buffer[0:16], buffer[0:16])
	return buffer[0:AkBufferSize]
}

// Computes full flyover MAC Vk based on authentication key Ak.
// Requires buffer to be of size at least FlyoverMacBufferSize
// Requires xkbuffer to be of size at least XkBufferSize.
// (Used to store the AES expanded keys)
func FullFlyoverMac(
	ak []byte,
	dstIA addr.IA,
	pktlen uint16,
	resStartTime uint16,
	highResTime uint32,
	buffer []byte,
	xkbuffer []uint32,
) []byte {

	// Bounds check.
	_ = buffer[FlyoverMacBufferSize-1]
	_ = xkbuffer[XkBufferSize-1]

	binary.BigEndian.PutUint64(buffer[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(buffer[8:10], pktlen)
	binary.BigEndian.PutUint16(buffer[10:12], resStartTime)
	binary.BigEndian.PutUint32(buffer[12:16], highResTime)

	expandKeyAsm(aesRounds, &ak[0], &xkbuffer[0])
	encryptBlockAsm(aesRounds, &xkbuffer[0], &buffer[0], &buffer[0])

	return buffer[0:FlyoverMacBufferSize]
}
