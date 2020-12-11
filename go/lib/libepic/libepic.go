// Copyright 2020 Anapaya Systems
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

package libepic

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"hash"
	"math"
	"time"

	"github.com/dchest/cmac"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
)

const (
	// Error messages
	ErrCipherFailure common.ErrMsg = "Unable to initialize AES cipher"
	ErrMacFailure    common.ErrMsg = "Unable to initialize Mac"
	// Maximal lifetime of a packet in milliseconds
	PacketLifetimeMs uint16 = 2000
	// Maximal clock skew in milliseconds
	ClockSkewMs uint16 = 1000
)

func initEpicMac(key []byte) (hash.Hash, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.Wrap(ErrCipherFailure, err)
	}
	// todo: CMAC is not ideal for EPIC due to its subkey generation overhead.
	// We might want to change this in the future.
	mac, err := cmac.New(block)
	if err != nil {
		return nil, serrors.Wrap(ErrMacFailure, err)
	}
	return mac, nil
}

//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | flags (1B) | timestamp (4B) | packetTimestamp (8B)  |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | srcIA (8B) | srcAddr (4/8/12/16B) | payloadLen (2B) |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | zero padding (0-15B)                                |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// The "flags" field only encodes the length of the source address.
func inputToBytes(timestamp uint32, packetTimestamp uint64,
	srcIA addr.IA, srcAddr []byte, srcAddrLen uint8, payloadLen uint16) ([]byte, error) {

	l := int((srcAddrLen + 1) * 4)
	if srcAddrLen > 3 || l != len(srcAddr) {
		return nil, serrors.New("srcAddrLen must be between 0 and 3, and encode the "+
			"srcAddr length", "srcAddrLen", srcAddrLen, "len(srcAddr)", len(srcAddr),
			"l", l)
	}

	// Create a multiple of 16 such that the input fits in
	nrBlocks := uint8(math.Ceil((23 + float64(l)) / 16))
	input := make([]byte, 16*nrBlocks)

	// Fill input
	input[0] = srcAddrLen
	binary.BigEndian.PutUint32(input[1:5], timestamp)
	binary.BigEndian.PutUint64(input[5:13], packetTimestamp)
	binary.BigEndian.PutUint64(input[13:21], uint64(srcIA.A))
	binary.BigEndian.PutUint16(input[13:15], uint16(srcIA.I))
	copy(input[21:(21+l)], srcAddr[:l])
	binary.BigEndian.PutUint16(input[(21+l):(23+l)], payloadLen)
	return input, nil
}

func PrepareMacInput(epicpath *epic.EpicPath, s *slayers.SCION, timestamp uint32) ([]byte, error) {
	if epicpath == nil {
		return nil, serrors.New("epicpath must not be nil")
	}
	if s == nil {
		return nil, serrors.New("SCION common+address header must not be nil")
	}
	packetTimestamp := epicpath.PacketTimestamp
	payloadLen := s.PayloadLen
	srcIA := s.SrcIA
	srcAddrLen := uint8(s.SrcAddrLen)
	srcAddr := s.RawSrcAddr
	return inputToBytes(timestamp, packetTimestamp, srcIA, srcAddr, srcAddrLen, payloadLen)
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             TsRel                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    CoreID     |                  CoreCounter                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func CreateEpicTimestamp(tsRel uint32, coreID uint8, coreCounter uint32) (packetTimestamp uint64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[4:8], coreCounter)
	binary.BigEndian.PutUint16(b[3:5], uint16(coreID))
	binary.BigEndian.PutUint32(b[:4], tsRel)
	packetTimestamp = binary.BigEndian.Uint64(b[:8])
	return
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             TsRel                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             PckId                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func CreateEpicTimestampCustom(tsRel uint32, pckId uint32) (packetTimestamp uint64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[:4], tsRel)
	binary.BigEndian.PutUint32(b[4:8], pckId)
	packetTimestamp = binary.BigEndian.Uint64(b[:8])
	return
}

func ParseEpicTimestamp(packetTimestamp uint64) (tsRel uint32, coreID uint8, coreCounter uint32) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b[:8], packetTimestamp)
	tsRel = binary.BigEndian.Uint32(b[:4])
	coreID = uint8(binary.BigEndian.Uint16(b[3:5]))
	coreCounter = binary.BigEndian.Uint32(b[4:8]) % (1 << 24)
	return tsRel, coreID, coreCounter
}

// CreateTsRel returns the current timestamp tsRel, which is calculated relative
// to the input timestamp (Unix time in seconds).
func CreateTsRel(timestamp uint32) (uint32, error) {
	tsMicro := uint64(timestamp) * 1000000
	nowMicro := uint64(time.Now().UnixNano() / 1000)
	var diff uint64
	if nowMicro < tsMicro {
		return 0, serrors.New("provided timestamp is in the future",
			"timestamp", tsMicro, "now", nowMicro)
	} else {
		diff = nowMicro - tsMicro
	}

	// Current time must be at most 1 day and 63 minutes after the timestamp
	tsRel := max(0, (diff/21)-1)
	if tsRel >= (1 << 32) {
		return 0, serrors.New("current time is more than 1 day"+
			"and 63 minutes after the timestamp",
			"timestamp", tsMicro, "now", nowMicro)
	}
	return uint32(tsRel), nil
}

func max(x, y uint64) uint64 {
	if x < y {
		return y
	}
	return x
}

func VerifyTimestamp(timestamp uint32, packetTimestamp uint64) bool {
	// Get unix time in microseconds when the packet was timestamped by the sender
	tsRel, _, _ := ParseEpicTimestamp(packetTimestamp)
	tsInfoMicro := uint64(timestamp) * 1000000
	tsSenderMicro := tsInfoMicro + ((uint64(tsRel) + 1) * 21)

	// Current unix time in microseconds
	nowMicro := uint64(time.Now().UnixNano() / 1000)

	// In milliseconds
	nowMs := nowMicro / 1000
	tsSenderMs := tsSenderMicro / 1000

	// Verification
	if (nowMs < tsSenderMs-uint64(ClockSkewMs)) ||
		(nowMs > tsSenderMs+uint64(PacketLifetimeMs)+uint64(ClockSkewMs)) {
		return false
	} else {
		return true
	}
}

func CalculateEpicMac(auth []byte, epicpath *epic.EpicPath, s *slayers.SCION,
	timestamp uint32) ([]byte, error) {

	// Initialize cryptographic MAC function
	f, err := initEpicMac(auth)
	if err != nil {
		return nil, err
	}
	// Prepare the input for the MAC function
	input, err := PrepareMacInput(epicpath, s, timestamp)
	if err != nil {
		return nil, err
	}
	// Calculate MAC ("Write" must not return an error: https://godoc.org/hash#Hash)
	if _, err := f.Write(input); err != nil {
		panic(err)
	}

	mac := f.Sum(nil)
	if len(mac) < 4 {
		return nil, serrors.New("calculated epic mac is too short")
	}
	return mac[:4], nil
}

// VerifyHVF verifies the correctness of the PHVF (if "last" is false)
// or the LHVF (if "last" is true).
func VerifyHVF(auth []byte, epicpath *epic.EpicPath, s *slayers.SCION,
	timestamp uint32, last bool) (bool, error) {

	if epicpath == nil || s == nil || len(auth) != 16 {
		return false, serrors.New("invalid input")
	}

	mac, err := CalculateEpicMac(auth, epicpath, s, timestamp)
	if err != nil {
		return false, err
	}

	var hvf []byte
	if last {
		hvf = epicpath.LHVF
	} else {
		hvf = epicpath.PHVF
	}
	return bytes.Equal(hvf, mac), nil
}

func IsPenultimateHop(scionRaw *scion.Raw) (bool, error) {
	if scionRaw == nil {
		return true, serrors.New("scion path must not be nil")
	}
	numberHops := scionRaw.NumHops
	currentHop := int(scionRaw.PathMeta.CurrHF)
	return currentHop == numberHops-2, nil
}

func IsLastHop(scionRaw *scion.Raw) (bool, error) {
	if scionRaw == nil {
		return true, serrors.New("scion path must not be nil")
	}
	numberHops := scionRaw.NumHops
	currentHop := int(scionRaw.PathMeta.CurrHF)
	return currentHop == numberHops-1, nil
}
