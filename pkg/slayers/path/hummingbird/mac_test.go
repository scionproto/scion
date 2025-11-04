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

package hummingbird_test

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
)

func TestDeriveAuthKey(t *testing.T) {
	sv := []byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	}
	var resId uint32 = 0x40
	var bw uint16 = 0x0203
	buffer := make([]byte, 16)
	var in uint16 = 2
	var eg uint16 = 5
	var start uint32 = 0x0030001
	var duration uint16 = 0x0203

	block, err := aes.NewCipher(sv)
	require.NoError(t, err)

	// Compute expected result with library CBC.
	expected := make([]byte, hummingbird.AkBufferSize)
	binary.BigEndian.PutUint16(expected[0:2], in)
	binary.BigEndian.PutUint16(expected[2:4], eg)
	binary.BigEndian.PutUint32(expected[4:8], resId<<10)
	expected[6] |= byte(bw >> 8)
	expected[7] = byte(bw)
	binary.BigEndian.PutUint32(expected[8:12], start)
	binary.BigEndian.PutUint16(expected[12:14], duration)
	binary.BigEndian.PutUint16(expected[14:16], 0)

	var ZeroBlock [aes.BlockSize]byte
	mode := cipher.NewCBCEncrypter(block, ZeroBlock[:])
	mode.CryptBlocks(expected, expected)

	// Check DeriveAuthKey Function.
	block, err = aes.NewCipher(sv)
	require.NoError(t, err)
	key := hummingbird.DeriveAuthKey(block, resId, bw, in, eg, start, duration, buffer)
	require.Equal(t, expected, key)
	// Repeat derivation, should yield the same result.
	key = hummingbird.DeriveAuthKey(block, resId, bw, in, eg, start, duration, buffer)
	require.Equal(t, expected, key)
}

func BenchmarkDeriveAuthKey(b *testing.B) {
	sv := []byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	}
	var resId uint32 = 0x40
	var bw uint16 = 0x0203
	buffer := make([]byte, hummingbird.AkBufferSize)
	var in uint16 = 2
	var eg uint16 = 5
	var start uint32 = 0x0030001
	var duration uint16 = 0x0203

	block, err := aes.NewCipher(sv)
	require.NoError(b, err)

	for b.Loop() {
		hummingbird.DeriveAuthKey(block, resId, bw, in, eg, start, duration, buffer)
	}
}

// BenchmarkDeriveAuthKeyManually benchmarks obtaining Ak by just using the stdlib.
// Results in my machine of 5.987 ns/op.
// Does not take into account the process of moving data into the buffer
func BenchmarkDeriveAuthKeyManually(b *testing.B) {
	sv := []byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	}
	var resId uint32 = 0x40
	var bw uint16 = 0x0203
	var in uint16 = 2
	var eg uint16 = 5
	var start uint16 = 0x0001
	var end uint16 = 0x0203
	inData := make([]byte, hummingbird.AkBufferSize)

	buffer := make([]byte, hummingbird.AkBufferSize)
	block, err := aes.NewCipher(sv)
	require.NoError(b, err)

	b.ResetTimer()
	for b.Loop() {
		binary.BigEndian.PutUint32(inData[0:4], resId<<10)
		inData[2] |= byte(bw >> 8)
		inData[3] = byte(bw)
		binary.BigEndian.PutUint16(inData[4:6], in)
		binary.BigEndian.PutUint16(inData[6:8], eg)
		binary.BigEndian.PutUint16(inData[8:10], start)
		binary.BigEndian.PutUint16(inData[10:12], end)
		binary.BigEndian.PutUint32(inData[12:16], 0) //padding
		block.Encrypt(buffer[:], inData)
	}
}

// We use CBC-MAC using aes for the flyover mac.
func TestFlyoverMac(t *testing.T) {
	ak := []byte{
		0x7e, 0x61, 0x04, 0x91, 0x30, 0x6b, 0x95, 0xec,
		0xb5, 0x75, 0xc6, 0xe9, 0x4c, 0x5a, 0x89, 0x84,
	}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	xkbuffer := make([]uint32, hummingbird.XkBufferSize)

	// Compute expected output based on library cbc-mac implementation.
	expected := make([]byte, hummingbird.FlyoverMacBufferSize)
	binary.BigEndian.PutUint64(expected[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(expected[8:10], pktlen)
	binary.BigEndian.PutUint16(expected[10:12], resStartTs)
	binary.BigEndian.PutUint32(expected[12:16], highResTs)
	block, err := aes.NewCipher(ak)
	require.NoError(t, err)
	block.Encrypt(expected[:], expected[:])

	mac := hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	require.Equal(t, expected, mac)
	// Repeat, to ensure that the result is the same despite using the same xk buffer.
	mac = hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	require.Equal(t, expected, mac)
}

func BenchmarkFlyoverMac(b *testing.B) {
	ak := []byte{
		0x7e, 0x61, 0x04, 0x91, 0x30, 0x6b, 0x95, 0xec,
		0xb5, 0x75, 0xc6, 0xe9, 0x4c, 0x5a, 0x89, 0x84,
	}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	xkbuffer := make([]uint32, hummingbird.XkBufferSize)

	b.ResetTimer()
	for b.Loop() {
		hummingbird.FullFlyoverMac(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	}
}

// Benchmark of the Flyover MAC if we use library code only
// Without using the assembly code in the asm_* files.
func BenchmarkFlyoverMacLib(b *testing.B) {
	ak := []byte{
		0x7e, 0x61, 0x04, 0x91, 0x30, 0x6b, 0x95, 0xec,
		0xb5, 0x75, 0xc6, 0xe9, 0x4c, 0x5a, 0x89, 0x84,
	}

	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, hummingbird.FlyoverMacBufferSize)

	// Compute expected output based on library cbc-mac implementation.
	b.ResetTimer()
	for b.Loop() {
		binary.BigEndian.PutUint64(buffer[0:8], uint64(dstIA))
		binary.BigEndian.PutUint16(buffer[8:10], pktlen)
		binary.BigEndian.PutUint16(buffer[10:12], resStartTs)
		binary.BigEndian.PutUint32(buffer[12:16], highResTs)

		block, _ := aes.NewCipher(ak)
		block.Encrypt(buffer[:], buffer[:])
	}
}
