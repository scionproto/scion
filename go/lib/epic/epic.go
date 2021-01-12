// Copyright 2020 ETH Zurich
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

package epic

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"math"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
)

const (
	// authLength denotes the size of the authenticator in bytes
	authLength = 16
	// packetLifetimeMs denotes the maximal lifetime of a packet in milliseconds
	packetLifetimeMs uint16 = 2000
	// clockSkewMs denotes the maximal clock skew in milliseconds
	clockSkewMs uint16 = 1000
)

// CreateEpicTimestamp creates the EPIC packetTimestamp from tsRel, coreID, and coreCounter.
func CreateEpicTimestamp(tsRel uint32, coreID uint8, coreCounter uint32) (packetTimestamp uint64) {
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                             TsRel                             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |    CoreID     |                  CoreCounter                  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[4:8], coreCounter)
	binary.BigEndian.PutUint16(b[3:5], uint16(coreID))
	binary.BigEndian.PutUint32(b[:4], tsRel)
	packetTimestamp = binary.BigEndian.Uint64(b[:8])
	return
}

// CreateEpicTimestampCustom creates the EPIC packetTimestamp from tsRel and pckId.
func CreateEpicTimestampCustom(tsRel uint32, pckId uint32) (packetTimestamp uint64) {
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                             TsRel                             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                             PckId                             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[:4], tsRel)
	binary.BigEndian.PutUint32(b[4:8], pckId)
	packetTimestamp = binary.BigEndian.Uint64(b[:8])
	return
}

// ParseEpicTimestamp reads tsRel, coreID, and coreCounter from the packetTimestamp.
func ParseEpicTimestamp(packetTimestamp uint64) (tsRel uint32, coreID uint8, coreCounter uint32) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b[:8], packetTimestamp)
	tsRel = binary.BigEndian.Uint32(b[:4])
	coreID = uint8(binary.BigEndian.Uint16(b[3:5]))
	coreCounter = binary.BigEndian.Uint32(b[4:8]) % (1 << 24)
	return tsRel, coreID, coreCounter
}

// CreateTsRel returns tsRel, which encodes the current time (the time when this function is called)
// relative to the input timestamp. The input timestamp must be specified in seconds since Unix
// time. It must not be in the future, otherwise an error is returned. The current time  must be at
// most 1 day and 63 minutes after the input timestamp, otherwise an error is returned.
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

// VerifyTimestamp checks whether an EPIC packet is fresh. This means that the time the packet
// was sent from the source host, which is encoded by the timestamp and the packetTimestamp,
// does not date back more than the maximal packet lifetime of two seconds. The function also takes
// a possible clock drift between the packet source and the verifier of up to one second into
// account.
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
	if (nowMs < tsSenderMs-uint64(clockSkewMs)) ||
		(nowMs > tsSenderMs+uint64(packetLifetimeMs)+uint64(clockSkewMs)) {
		return false
	} else {
		return true
	}
}

// CalculateEpicMac derives the EPIC MAC (PHVF/LHVF) given the full 16 bytes of the SCION path type
// MAC (auth), the EPIC path type header (epicpath), and the SCION common/address header (s).
func CalculateEpicMac(auth []byte, epicpath *epic.EpicPath, s *slayers.SCION,
	timestamp uint32) ([]byte, error) {

	// Initialize cryptographic MAC function
	f, err := initEpicMac(auth)
	if err != nil {
		return nil, err
	}
	// Prepare the input for the MAC function
	input, err := prepareMacInput(epicpath, s, timestamp)
	if err != nil {
		return nil, err
	}
	if len(input) < 16 || len(input)%16 != 0 {
		return nil, serrors.New("epic mac input has invalid length", "expected", 16,
			"is", len(input))
	}
	// Calculate Epic MAC = first 4 bytes of the last CBC block
	mac := make([]byte, len(input))
	f.CryptBlocks(mac, input)
	return mac[len(mac)-16 : len(mac)-12], nil
}

// VerifyHVFIfNecessary verifies the correctness of the HVF if necessary, i.e., if the current hop
// is either the penultimate or the last hop of the path.
func VerifyHVFIfNecessary(scionRaw *scion.Raw, auth []byte, epicpath *epic.EpicPath,
	s *slayers.SCION, timestamp uint32) (bool, error) {

	IsPenHop, errPenHop := isPenultimateHop(scionRaw)
	if errPenHop != nil {
		return false, errPenHop
	}
	IsLastHop, errLastHop := isLastHop(scionRaw)
	if errLastHop != nil {
		return false, errLastHop
	}

	switch {
	case IsPenHop:
		return VerifyHVF(auth, epicpath, s, timestamp, false)
	case IsLastHop:
		return VerifyHVF(auth, epicpath, s, timestamp, true)
	default:
		return true, nil
	}
}

// VerifyHVF verifies the correctness of the PHVF (if "last" is false) or the LHVF (if "last" is
// true) field in the EPIC packet by recalculating and comparing them. If the EPIC
// authenticator (auth), which denotes the full 16 bytes of the SCION path type MAC, has invalid
// length, or if the MAC calculation gives an error, also VerifyHVF returns an error.
func VerifyHVF(auth []byte, epicpath *epic.EpicPath, s *slayers.SCION,
	timestamp uint32, last bool) (bool, error) {

	if epicpath == nil || s == nil || len(auth) != authLength {
		return false, serrors.New("invalid input")
	}

	mac, err := CalculateEpicMac(auth, epicpath, s, timestamp)
	if err != nil {
		return false, err
	}

	hvf := epicpath.PHVF
	if last {
		hvf = epicpath.LHVF
	}
	return bytes.Equal(hvf, mac), nil
}

// isPenultimateHop returns whether the current hop is the penultimate hop on the path.
// It returns an error if scionRaw is nil.
func isPenultimateHop(scionRaw *scion.Raw) (bool, error) {
	if scionRaw == nil {
		return true, serrors.New("scion path must not be nil")
	}
	numberHops := scionRaw.NumHops
	currentHop := int(scionRaw.PathMeta.CurrHF)
	return currentHop == numberHops-2, nil
}

// isLastHop returns whether the current hop is the last hop on the path.
// It returns an error if scionRaw is nil.
func isLastHop(scionRaw *scion.Raw) (bool, error) {
	if scionRaw == nil {
		return true, serrors.New("scion path must not be nil")
	}
	numberHops := scionRaw.NumHops
	currentHop := int(scionRaw.PathMeta.CurrHF)
	return currentHop == numberHops-1, nil
}

func initEpicMac(key []byte) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.New("Unable to initialize AES cipher")
	}

	// Zero initialization vector
	zeroInitVector := make([]byte, 16)
	// CBC-MAC = CBC-Encryption with zero initialization vector
	mode := cipher.NewCBCEncrypter(block, zeroInitVector)
	return mode, nil
}

func inputToBytes(timestamp uint32, packetTimestamp uint64,
	srcIA addr.IA, srcAddr []byte, srcAddrLen uint8, payloadLen uint16) ([]byte, error) {

	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   | flags (1B) | timestamp (4B) | packetTimestamp (8B)  |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   | srcIA (8B) | srcAddr (4/8/12/16B) | payloadLen (2B) |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   | zero padding (0-15B)                                |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// The "flags" field only encodes the length of the source address.

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

func prepareMacInput(epicpath *epic.EpicPath, s *slayers.SCION, timestamp uint32) ([]byte, error) {
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

func max(x, y uint64) uint64 {
	if x < y {
		return y
	}
	return x
}
