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

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
)

const (
	// AuthLen denotes the size of the authenticator in bytes
	AuthLen = 16
	// MaxPacketLifetime denotes the maximal lifetime of a packet in microseconds
	MaxPacketLifetime uint32 = 2000000
	// MaxClockSkew denotes the maximal clock skew in microseconds
	MaxClockSkew uint32 = 1000000
)

// CreateTimestamp returns tsRel, which encodes the current time (nowNanoseconds)
// relative to the input timestamp. The input timestamp must be specified in seconds since Unix
// time. The current time (nowNanoseconds) must be specified in nanoseconds since Unix time.
// The input timestamp must not be in the future (compared to the current time), otherwise an error
// is returned. The current time  must be at most 1 day and 63 minutes after the input timestamp,
// otherwise an error is returned.
func CreateTimestamp(input uint32, nowNanoseconds int64) (uint32, error) {
	tsMicro := uint64(input) * 1000000
	nowMicro := uint64(nowNanoseconds / 1000)
	if nowMicro < tsMicro {
		return 0, serrors.New("provided input timestamp is in the future",
			"input timestamp", tsMicro, "now", nowMicro)
	}
	diff := nowMicro - tsMicro

	// Current time must be at most 1 day and 63 minutes after the timestamp
	tsRel := max(0, (diff/21)-1)
	if tsRel >= (1 << 32) {
		return 0, serrors.New("diff between input and now >1d63min",
			"diff", time.Duration(diff*1000).String())
	}
	return uint32(tsRel), nil
}

// VerifyTimestamp checks whether an EPIC packet is fresh. This means that the time the packet
// was sent from the source host, which is encoded by the timestamp and the packetTimestamp,
// does not date back more than the maximal packet lifetime of two seconds. The function also takes
// a possible clock drift between the packet source and the verifier of up to one second into
// account.
func VerifyTimestamp(timestamp uint32, packetTimestamp uint32, nowNanoseconds int64) error {
	// Get unix time in microseconds when the packet was timestamped by the sender
	tsInfoMicro := uint64(timestamp) * 1000000
	tsSenderMicro := tsInfoMicro + ((uint64(packetTimestamp) + 1) * 21)

	// Current unix time in microseconds
	nowMicro := uint64(nowNanoseconds / 1000)

	// Verification
	if nowMicro < tsSenderMicro-uint64(MaxClockSkew) {
		delta := tsSenderMicro - uint64(MaxClockSkew) - nowMicro
		return serrors.New("epic packet timestamp is in the future",
			"delta", time.Duration(delta).String())
	}
	if nowMicro > tsSenderMicro+uint64(MaxPacketLifetime)+uint64(MaxClockSkew) {
		delta := nowMicro - tsSenderMicro - uint64(MaxPacketLifetime) - uint64(MaxClockSkew)
		return serrors.New("epic packet timestamp expired",
			"delta", time.Duration(delta).String())
	}
	return nil
}

// CalcMac derives the EPIC MAC (PHVF/LHVF) given the full 16 bytes of the SCION path type
// MAC (auth), the EPIC packet ID (pktID), the timestamp in the Info Field (timestamp),
// and the SCION common/address header (s).
func CalcMac(auth []byte, pktID *epic.PktID, s *slayers.SCION,
	timestamp uint32) ([]byte, error) {

	// Initialize cryptographic MAC function
	f, err := initEpicMac(auth)
	if err != nil {
		return nil, err
	}
	// Prepare the input for the MAC function
	input, err := prepareMacInput(pktID, s, timestamp)
	if err != nil {
		return nil, err
	}
	// Calculate Epic MAC = first 4 bytes of the last CBC block
	mac := make([]byte, len(input))
	f.CryptBlocks(mac, input)
	return mac[len(mac)-f.BlockSize() : len(mac)-f.BlockSize()+4], nil
}

// VerifyHVF verifies the correctness of the HVF (PHVF or the LHVF) field in the EPIC packet by
// recalculating and comparing it. If the EPIC authenticator (auth), which denotes the full 16
// bytes of the SCION path type MAC, has invalid length, or if the MAC calculation gives an error,
// also VerifyHVF returns an error. The verification was successful if and only if VerifyHVF
// returns nil.
func VerifyHVF(auth []byte, pktID *epic.PktID, s *slayers.SCION,
	timestamp uint32, hvf []byte) error {

	if pktID == nil || s == nil || len(auth) != AuthLen {
		return serrors.New("invalid input")
	}

	mac, err := CalcMac(auth, pktID, s, timestamp)
	if err != nil {
		return err
	}

	if !bytes.Equal(hvf, mac) {
		return serrors.New("epic hop validation field verification failed",
			"hvf in packet", hvf, "calculated mac", mac)
	}
	return nil
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

func prepareMacInput(pktID *epic.PktID, s *slayers.SCION, timestamp uint32) ([]byte, error) {
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   | flags (1B) | timestamp (4B) |    packet ID (8B)     |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   | srcIA (8B) | srcAddr (4/8/12/16B) | payloadLen (2B) |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   | zero padding (0-15B)                                |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// The "flags" field only encodes the length of the source address.

	if pktID == nil {
		return nil, serrors.New("pktID must not be nil")
	}
	if s == nil {
		return nil, serrors.New("SCION common+address header must not be nil")
	}
	srcAddrLen := uint8(s.SrcAddrLen)
	srcAddr := s.RawSrcAddr

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
	pktID.SerializeTo(input[5:13])
	binary.BigEndian.PutUint64(input[13:21], uint64(s.SrcIA.A))
	binary.BigEndian.PutUint16(input[13:15], uint16(s.SrcIA.I))
	copy(input[21:(21+l)], srcAddr[:l])
	binary.BigEndian.PutUint16(input[(21+l):(23+l)], s.PayloadLen)
	return input, nil
}

func max(x, y uint64) uint64 {
	if x < y {
		return y
	}
	return x
}
