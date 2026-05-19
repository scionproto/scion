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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2s"

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

// BenchmarkDeriveAuthKey measures the performance of the DeriveAuthKey function.
// This benchmark is relevant to the border router, who keeps an existing block, and always
// needs to derive a new Ak for every packet.
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

// BenchmarkDeriveAuthKeyStdLib benchmarks obtaining Ak by just using the stdlib.
// Results in my machine of 5.987 ns/op.
// Does not take into account the process of moving data into the buffer
func BenchmarkDeriveAuthKeyStdLib(b *testing.B) {
	sv := []byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	}
	var resId uint32 = 0x40
	var bw uint16 = 0x0203
	var in uint16 = 2
	var eg uint16 = 5
	var start uint32 = 0x0030001
	var duration uint16 = 0x0203

	buffer := make([]byte, hummingbird.AkBufferSize)
	block, err := aes.NewCipher(sv)
	require.NoError(b, err)

	b.ResetTimer()
	for b.Loop() {
		func() {
			_ = buffer[hummingbird.AkBufferSize-1]

			binary.BigEndian.PutUint16(buffer[0:2], in)
			binary.BigEndian.PutUint16(buffer[2:4], eg)
			binary.BigEndian.PutUint32(buffer[4:8], resId<<10|uint32(bw))
			binary.BigEndian.PutUint32(buffer[8:12], start)
			binary.BigEndian.PutUint16(buffer[12:14], duration)
			binary.BigEndian.PutUint16(buffer[14:16], 0) //padding
			block.Encrypt(buffer, buffer)
		}()
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

func TestExpandAES128KeyAndEncryptBlockExpanded(t *testing.T) {
	ak := []byte{
		0x7e, 0x61, 0x04, 0x91, 0x30, 0x6b, 0x95, 0xec,
		0xb5, 0x75, 0xc6, 0xe9, 0x4c, 0x5a, 0x89, 0x84,
	}
	input := []byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15,
	}
	xkbuffer := make([]uint32, hummingbird.XkBufferSize)

	expected := append([]byte(nil), input...)
	block, err := aes.NewCipher(ak)
	require.NoError(t, err)
	block.Encrypt(expected, expected)

	got := append([]byte(nil), input...)
	expandAES128KeyTest(ak, xkbuffer)
	encryptAES128BlockExpandedTest(xkbuffer, got)

	require.Equal(t, expected, got)
}

func TestFullFlyoverMacGoMatchesAssembly(t *testing.T) {
	ak := []byte{
		0x7e, 0x61, 0x04, 0x91, 0x30, 0x6b, 0x95, 0xec,
		0xb5, 0x75, 0xc6, 0xe9, 0x4c, 0x5a, 0x89, 0x84,
	}
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	goBuffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	goXkbuffer := make([]uint32, hummingbird.XkBufferSize)
	asmBuffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	asmXkbuffer := make([]uint32, hummingbird.XkBufferSize)

	goMAC := fullFlyoverMacGoTest(
		ak, dstIA, pktlen, resStartTs, highResTs, goBuffer, goXkbuffer,
	)
	asmMAC := hummingbird.FullFlyoverMacAsm(
		ak, dstIA, pktlen, resStartTs, highResTs, asmBuffer, asmXkbuffer,
	)

	require.Equal(t, asmMAC, goMAC)
}

// BenchmarkFlyoverMacGo measures the performance of the pure-Go expanded-key implementation.
func BenchmarkFlyoverMacGo(b *testing.B) {
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
		fullFlyoverMacGoTest(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	}
}

// BenchmarkFlyoverMacAsm measures the performance of the preserved assembly-backed path.
func BenchmarkFlyoverMacAsm(b *testing.B) {
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
		hummingbird.FullFlyoverMacAsm(ak, dstIA, pktlen, resStartTs, highResTs, buffer, xkbuffer)
	}
}

// BenchmarkFlyoverMacStdLib measures the performance of the Flyover MAC if we use
// standard library code only, without using the assembly code in the asm_* files.
func BenchmarkFlyoverMacStdLib(b *testing.B) {
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

func BenchmarkExpandAES128Key(b *testing.B) {
	ak := []byte{
		0x7e, 0x61, 0x04, 0x91, 0x30, 0x6b, 0x95, 0xec,
		0xb5, 0x75, 0xc6, 0xe9, 0x4c, 0x5a, 0x89, 0x84,
	}
	xkbuffer := make([]uint32, hummingbird.XkBufferSize)

	b.ResetTimer()
	for b.Loop() {
		expandAES128KeyTest(ak, xkbuffer)
	}
}

func BenchmarkEncryptAES128BlockExpanded(b *testing.B) {
	ak := []byte{
		0x7e, 0x61, 0x04, 0x91, 0x30, 0x6b, 0x95, 0xec,
		0xb5, 0x75, 0xc6, 0xe9, 0x4c, 0x5a, 0x89, 0x84,
	}
	xkbuffer := make([]uint32, hummingbird.XkBufferSize)
	buffer := make([]byte, hummingbird.FlyoverMacBufferSize)

	expandAES128KeyTest(ak, xkbuffer)
	b.ResetTimer()
	for b.Loop() {
		copy(buffer, []byte{
			0, 1, 2, 3, 4, 5, 6, 7,
			8, 9, 10, 11, 12, 13, 14, 15,
		})
		encryptAES128BlockExpandedTest(xkbuffer, buffer)
	}
}

func BenchmarkFlyoverMacRouterLike(b *testing.B) {
	sv := []byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	}
	var resID uint32 = 0x40
	var bw uint16 = 0x0203
	var in uint16 = 2
	var eg uint16 = 5
	var start uint32 = 0x0030001
	var duration uint16 = 0x0203
	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, hummingbird.MACBufferSize)
	xkbuffer := make([]uint32, hummingbird.XkBufferSize)

	block, err := aes.NewCipher(sv)
	require.NoError(b, err)

	b.ResetTimer()
	for b.Loop() {
		ak := hummingbird.DeriveAuthKey(
			block, resID, bw, in, eg, start, duration,
			buffer[hummingbird.FlyoverMacBufferSize:],
		)
		fullFlyoverMacGoTest(
			ak, dstIA, pktlen, resStartTs, highResTs,
			buffer[:hummingbird.FlyoverMacBufferSize], xkbuffer,
		)
	}
}

// BenchmarkFullFlyoverMacEndhost measures the time needed to derive a MAC given a fixed Ak.
// This is relevant for the endhost, as it can cache the AES Block derived from Ak,
// and reuse it to compute each MAC as the values change.
func BenchmarkFullFlyoverMacEndhost(b *testing.B) {
	ak := []byte{
		0x7e, 0x61, 0x04, 0x91, 0x30, 0x6b, 0x95, 0xec,
		0xb5, 0x75, 0xc6, 0xe9, 0x4c, 0x5a, 0x89, 0x84,
	}

	var dstIA addr.IA = 326
	var pktlen uint16 = 23
	var resStartTs uint16 = 1234
	var highResTs uint32 = 4321
	buffer := make([]byte, hummingbird.FlyoverMacBufferSize)

	// Derive the AES block once, like the end-host would do.
	// Keep it for posterior computations of the MAC.
	block, err := aes.NewCipher(ak)
	require.NoError(b, err)

	// Compute expected output based on library cbc-mac implementation.
	b.ResetTimer()
	for b.Loop() {
		hummingbird.FlyoverMacWithAkAesBlock(block, buffer, dstIA, pktlen, resStartTs, highResTs)
	}
}

func BenchmarkMacAlternatives(b *testing.B) {
	const (
		AkSize  = hummingbird.AkBufferSize
		MacSize = hummingbird.FlyoverMacBufferSize
	)
	ak := []byte{
		0x7e, 0x61, 0x04, 0x91, 0x30, 0x6b, 0x95, 0xec,
		0xb5, 0x75, 0xc6, 0xe9, 0x4c, 0x5a, 0x89, 0x84,
	}

	b.Run(
		// AesEncrypt just calls AES encrypt. Times for my machine.
		// 13.40 ns/op
		"AesEncrypt", func(b *testing.B) {
			buffer := make([]byte, MacSize)
			block, err := aes.NewCipher(ak)
			require.NoError(b, err)

			b.ResetTimer()
			for b.Loop() {
				block.Encrypt(buffer[:16], buffer[:16])
			}
		},
	)

	b.Run("HMAC", func(b *testing.B) {
		// Alternative using an HMAC with SHA256.
		// 478.3 ns/op
		buffer := make([]byte, MacSize)
		h := hmac.New(sha256.New, ak)
		b.ResetTimer()
		for b.Loop() {
			h.Reset()
			h.Write(buffer)
			h.Sum(nil)
		}
	},
	)

	b.Run("BLAKE2s", func(b *testing.B) {
		// Keyed hash using BLAKE2s approach.
		// 234.7 ns/op
		buffer := make([]byte, MacSize)
		h, err := blake2s.New256(ak)
		require.NoError(b, err)
		var fullMac [32]byte

		b.ResetTimer()
		for b.Loop() {
			h.Reset()
			h.Write(buffer)
			h.Sum(fullMac[:0])
		}
	})

}
