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

//go:generate go run github.com/scionproto/scion/tools/gen_hbird_aesasm

package hummingbird

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path"
)

// The original implementation of FullFlyoverMac used assembly helpers copied from the
// Go AES implementation to avoid per-call allocations and the hidden key schedule work
// inside aes.NewCipher. The assembly-backed path remains the default implementation.

// Bazel builds regenerate the copied AES assembly automatically. Run
// `go generate ./pkg/slayers/path/hummingbird` to refresh the checked-in files for
// raw `go build` workflows.

// defined in asm_* assembly files

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc, dec *uint32)

const (
	PathType = 5
	// SecretValueDerivationSalt is the PBKDF2 salt used to derive the Hummingbird AS secret value.
	SecretValueDerivationSalt = "Derive hbird sv"

	AkBufferSize         = 16
	FlyoverMacBufferSize = 16

	aesRounds        = 10
	aesRoundKeyWords = (aesRounds + 1) * (128 / 32) // 44
	XkBufferSize     = 2 * aesRoundKeyWords         // enc + dec key schedule
	// Total MAC buffer size:
	MACBufferSize = path.MACBufferSize + FlyoverMacBufferSize + AkBufferSize
)

// DeriveSecretValue derives the Hummingbird AS secret value from the master secret.
func DeriveSecretValue(masterSecret []byte) []byte {
	if len(masterSecret) == 0 {
		panic("empty key")
	}
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	return pbkdf2.Key(masterSecret, []byte(SecretValueDerivationSalt), 1000, 16, sha256.New)
}

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

// Computes full flyover MAC Vk based on authentication key Ak using the assembly-backed
// AES helpers copied from the Go standard library.
func FullFlyoverMac(
	ak []byte,
	dstIA addr.IA,
	pktlen uint16,
	resStartTime uint16,
	highResTime uint32,
	buffer []byte,
	xkbuffer []uint32,
) []byte {
	return FullFlyoverMacAsm(ak, dstIA, pktlen, resStartTime, highResTime, buffer, xkbuffer)
}

// FullFlyoverMacAsm uses the assembly-backed AES helpers.
func FullFlyoverMacAsm(
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

	expandKeyAsm(aesRounds, &ak[0], &xkbuffer[0], &xkbuffer[aesRoundKeyWords])
	encryptBlockAsm(aesRounds, &xkbuffer[0], &buffer[0], &buffer[0])

	return buffer[0:FlyoverMacBufferSize]
}

// FlyoverMacWithAkAesBlock computes the MAC for a Hummingbird packet, given an existing
// block obtained with e.g. block:=aes.NewCipher(ak), and a preallocated buffer of at least
// AkBufferSize bytes.
func FlyoverMacWithAkAesBlock(
	block cipher.Block,
	buffer []byte,
	dstIA addr.IA,
	pktlen uint16,
	resStartTime uint16,
	highResTime uint32,
) []byte {
	_ = buffer[AkBufferSize-1]

	binary.BigEndian.PutUint64(buffer[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(buffer[8:10], pktlen)
	binary.BigEndian.PutUint16(buffer[10:12], resStartTime)
	binary.BigEndian.PutUint32(buffer[12:16], highResTime)

	block.Encrypt(buffer[:AkBufferSize], buffer[:AkBufferSize])
	return buffer[:AkBufferSize]
}
