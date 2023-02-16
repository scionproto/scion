// Copyright 2022 ETH Zurich
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

package spao

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/dchest/cmac"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

const (
	// FixAuthDataInputLen is the unvariable fields length for the
	// authenticated data. It consists of the Authenticator Option Metadata
	// length and the SCION Common Header without the second row.
	fixAuthDataInputLen = slayers.PacketAuthOptionMetadataLen +
		slayers.CmnHdrLen - slayers.LineLen
	// MACBufferSize sets an upperBound to the authenticated data
	// length (excluding the payload). This is:
	// 1. Authenticator Option Meta
	// 2. SCION Common Header
	// 3. SCION Address Header
	// 4. Path
	// (see https://docs.scion.org/en/latest/protocols/authenticator-option.html#authenticated-data)
	// We round this up to 12B (authenticator option meta) + 1020B (max SCION header length)
	// To adapt to any possible path types.
	MACBufferSize = 1032
)

type MACInput struct {
	Key        []byte
	Header     slayers.PacketAuthOption
	ScionLayer *slayers.SCION
	PldType    slayers.L4ProtocolType
	Pld        []byte
}

// ComputeAuthCMAC computes the authenticator tag for the AES-CMAC algorithm.
// The key should correspond to the SPI defined in opt.SPI.
// The SCION layer, payload type and payload define the input to the MAC, as defined in
// https://docs.scion.org/en/latest/protocols/authenticator-option.html#authenticated-data.
//
// The aux buffer is used as a temporary buffer for the MAC computation.
// It must be at least MACBufferSize long.
// The resulting MAC is written to outBuffer (appending, if necessary),
// and returned as a slice of length 16.
func ComputeAuthCMAC(
	input MACInput,
	auxBuffer []byte,
	outBuffer []byte,
) ([]byte, error) {

	cmac, err := initCMAC(input.Key)
	if err != nil {
		return nil, err
	}
	inputLen, err := serializeAuthenticatedData(
		auxBuffer,
		input.ScionLayer,
		input.Header,
		input.PldType,
		input.Pld,
	)
	if err != nil {
		return nil, err
	}
	cmac.Write(auxBuffer[:inputLen])
	cmac.Write(input.Pld)
	return cmac.Sum(outBuffer[:0]), nil
}

func initCMAC(key []byte) (hash.Hash, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.WrapStr("unable to initialize AES cipher", err)
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, serrors.WrapStr("unable to initialize Mac", err)
	}
	return mac, nil
}

func serializeAuthenticatedData(
	buf []byte,
	s *slayers.SCION,
	opt slayers.PacketAuthOption,
	pldType slayers.L4ProtocolType,
	pld []byte,
) (int, error) {

	_ = buf[MACBufferSize-1]

	hdrLen := slayers.CmnHdrLen + s.AddrHdrLen() + s.Path.Len()
	if hdrLen > slayers.MaxHdrLen {
		return 0, serrors.New("SCION header length exceeds maximum",
			"max", slayers.MaxHdrLen, "actual", hdrLen)
	}
	if hdrLen%slayers.LineLen != 0 {
		return 0, serrors.New("SCION header length is not an integer multiple of line length",
			"actual", hdrLen)
	}

	buf[0] = byte(hdrLen / slayers.LineLen)
	buf[1] = byte(pldType)
	binary.BigEndian.PutUint16(buf[2:], uint16(len(pld)))
	buf[4] = byte(opt.Algorithm())
	buf[5] = byte(opt.Timestamp() >> 16)
	buf[6] = byte(opt.Timestamp() >> 8)
	buf[7] = byte(opt.Timestamp())
	buf[8] = byte(0)
	buf[9] = byte(opt.SequenceNumber() >> 16)
	buf[10] = byte(opt.SequenceNumber() >> 8)
	buf[11] = byte(opt.SequenceNumber())
	firstHdrLine := uint32(s.Version&0xF)<<28 | uint32(s.TrafficClass&0x3f)<<20 | s.FlowID&0xFFFFF
	binary.BigEndian.PutUint32(buf[12:], firstHdrLine)
	buf[16] = byte(s.PathType)
	buf[17] = byte(s.DstAddrType&0x7)<<4 | byte(s.SrcAddrType&0x7)
	binary.BigEndian.PutUint16(buf[18:], 0)
	offset := fixAuthDataInputLen

	if !opt.SPI().IsDRKey() {
		binary.BigEndian.PutUint64(buf[offset:], uint64(s.DstIA))
		binary.BigEndian.PutUint64(buf[offset+8:], uint64(s.SrcIA))
		offset += 16
	}
	if !opt.SPI().IsDRKey() ||
		(opt.SPI().Type() == slayers.PacketAuthASHost &&
			opt.SPI().Direction() == slayers.PacketAuthReceiverSide) {
		offset += copy(buf[offset:], s.RawDstAddr)
	}
	if !opt.SPI().IsDRKey() ||
		(opt.SPI().Type() == slayers.PacketAuthASHost &&
			opt.SPI().Direction() == slayers.PacketAuthSenderSide) {
		offset += copy(buf[offset:], s.RawSrcAddr)
	}
	err := zeroOutMutablePath(s.Path, buf[offset:])
	if err != nil {
		return 0, err
	}
	offset += s.Path.Len()
	return offset, nil
}

func zeroOutMutablePath(orig path.Path, buf []byte) error {
	err := orig.SerializeTo(buf)
	if err != nil {
		return serrors.WrapStr("serializing path for resetting fields", err)
	}
	switch p := orig.(type) {
	case empty.Path:
		return nil
	case *scion.Raw:
		zeroOutWithBase(p.Base, buf)
		return nil
	case *scion.Decoded:
		zeroOutWithBase(p.Base, buf)
		return nil
	case *epic.Path:
		zeroOutWithBase(p.ScionPath.Base, buf[epic.MetadataLen:])
		return nil
	case *onehop.Path:
		// Zero out IF.SegID
		binary.BigEndian.PutUint16(buf[2:], 0)
		// Zero out HF.Flags&&Alerts
		buf[8] = 0
		// Zero out second HF
		copy(buf[20:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		return nil
	default:
		return serrors.New(fmt.Sprintf("unknown path type %T", orig))
	}
}

func zeroOutWithBase(base scion.Base, buf []byte) {
	// Zero out CurrInf && CurrHF
	offset := 0
	buf[offset] = 0
	offset += 4
	for i := 0; i < base.NumINF; i++ {
		// Zero out IF.SegID
		binary.BigEndian.PutUint16(buf[offset+2:], 0)
		offset += 8
	}
	for i := 0; i < base.NumINF; i++ {
		for j := 0; j < int(base.PathMeta.SegLen[i]); j++ {
			// Zero out HF.Flags&&Alerts
			buf[offset] = 0
			offset += 12
		}
	}
}
