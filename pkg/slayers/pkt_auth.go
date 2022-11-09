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

// This file includes the SPAO header implementation as specified
// in https://docs.scion.org/en/latest/protocols/authenticator-option.html

// The Authenticator option format is as follows:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   NextHdr=UDP |     ExtLen    |  OptType=2    |  OptDataLen   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Security Parameter Index                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Algorithm  |                    Timestamp                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      RSV      |                  Sequence Number              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                        16-octet MAC data                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

package slayers

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"hash"
	"time"

	"github.com/dchest/cmac"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

const (
	PacketAuthASHost uint8 = iota
	PacketAuthHostHost
)

const (
	PacketAuthSenderSide uint8 = iota
	PacketAuthReceiverSide
)

const (
	PacketAuthLater uint8 = iota
	PacketAuthEarlier
)

const (
	// MinPacketAuthDataLen is the minimum size of the SPAO OptData.
	// The SPAO header contains the following fixed-length fields:
	// SPI (4 Bytes), Algorithm (1 Byte), Timestamp (3 Bytes),
	// RSV (1 Byte) and Sequence Number (3 Bytes).
	MinPacketAuthDataLen = 12
	// FixAuthDataInputLen is the unvariable fields length for the
	// authenticated data
	FixAuthDataInputLen = MinPacketAuthDataLen + 8
	// UpperBoundMACInput sets an upperBound to the authenticated data
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

// PacketAuthSPI (Security Parameter Index) is the identifier for the key
// used for the packet authentication option. DRKey values are in the
// range [1, 2^21-1].
type PacketAuthSPI uint32

func (p PacketAuthSPI) Type() uint8 {
	if p&(1<<18) == 0 {
		return PacketAuthASHost
	}
	return PacketAuthHostHost
}

func (p PacketAuthSPI) Direction() uint8 {
	if p&(1<<17) == 0 {
		return PacketAuthSenderSide
	}
	return PacketAuthReceiverSide
}

func (p PacketAuthSPI) Epoch() uint8 {
	if p&(1<<16) == 0 {
		return PacketAuthLater
	}
	return PacketAuthEarlier
}

func (p PacketAuthSPI) DRKeyProto() uint16 {
	return uint16(p)
}

func (p PacketAuthSPI) IsDRKey() bool {
	return p > 0 && p < (1<<21)
}

func MakePacketAuthSPIDRKey(
	proto uint16,
	drkeyType uint8,
	dir uint8,
	epoch uint8,
) (PacketAuthSPI, error) {

	if proto < 1 {
		return 0, serrors.New("Invalid proto identifier value")
	}
	if drkeyType > 1 {
		return 0, serrors.New("Invalid DRKeyType value")
	}
	if dir > 1 {
		return 0, serrors.New("Invalid DRKeyDirection value")
	}
	if epoch > 1 {
		return 0, serrors.New("Invalid DRKeyEpochType value")
	}
	spi := uint32((drkeyType & 0x1)) << 18
	spi |= uint32((dir & 0x1)) << 17
	spi |= uint32((epoch & 0x1)) << 16
	spi |= uint32(proto)

	return PacketAuthSPI(spi), nil
}

// PacketAuthAlg is the enumerator for authenticator algorithm types in the
// packet authenticator option.
type PacketAuthAlg uint8

const (
	PacketAuthCMAC PacketAuthAlg = iota
	PacketAuthSHA1_AES_CBC
)

type PacketAuthOptionParams struct {
	SPI            PacketAuthSPI
	Algorithm      PacketAuthAlg
	Timestamp      uint32
	SequenceNumber uint32
	Auth           []byte
}

// PacketAuthOption wraps an EndToEndOption of OptTypeAuthenticator.
// This can be used to serialize and parse the internal structure of the packet authenticator
// option.
type PacketAuthOption struct {
	*EndToEndOption
}

// NewPacketAuthOption creates a new EndToEndOption of
// OptTypeAuthenticator, initialized with the given SPAO data.
func NewPacketAuthOption(
	p PacketAuthOptionParams,
) (PacketAuthOption, error) {

	o := PacketAuthOption{EndToEndOption: new(EndToEndOption)}
	err := o.Reset(p)
	return o, err
}

// ParsePacketAuthOption parses o as a packet authenticator option.
// Performs minimal checks to ensure that SPI, algorithm, timestamp, RSV, and
// sequence number are set.
// Checking the size and content of the Authenticator data must be done by the
// caller.
func ParsePacketAuthOption(o *EndToEndOption) (PacketAuthOption, error) {
	if o.OptType != OptTypeAuthenticator {
		return PacketAuthOption{},
			serrors.New("wrong option type", "expected", OptTypeAuthenticator, "actual", o.OptType)
	}
	if len(o.OptData) < MinPacketAuthDataLen {
		return PacketAuthOption{},
			serrors.New("buffer too short", "expected at least", 12, "actual", len(o.OptData))
	}
	return PacketAuthOption{o}, nil
}

// Reset reinitializes the underlying EndToEndOption with the SPAO data.
// Reuses the OptData buffer if it is of sufficient capacity.
func (o PacketAuthOption) Reset(
	p PacketAuthOptionParams,
) error {

	if p.Timestamp >= (1 << 24) {
		return serrors.New("Timestamp value should be smaller than 2^24")
	}
	if p.SequenceNumber >= (1 << 24) {
		return serrors.New("Sequence number should be smaller than 2^24")
	}

	o.OptType = OptTypeAuthenticator

	n := MinPacketAuthDataLen + len(p.Auth)
	if n <= cap(o.OptData) {
		o.OptData = o.OptData[:n]
	} else {
		o.OptData = make([]byte, n)
	}
	binary.BigEndian.PutUint32(o.OptData[:4], uint32(p.SPI))
	o.OptData[4] = byte(p.Algorithm)
	o.OptData[5] = byte(p.Timestamp >> 16)
	o.OptData[6] = byte(p.Timestamp >> 8)
	o.OptData[7] = byte(p.Timestamp)
	o.OptData[8] = byte(0)
	o.OptData[9] = byte(p.SequenceNumber >> 16)
	o.OptData[10] = byte(p.SequenceNumber >> 8)
	o.OptData[11] = byte(p.SequenceNumber)
	copy(o.OptData[12:], p.Auth)

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
	return nil
}

// SPI returns the value set in the Security Parameter Index in the extension.
func (o PacketAuthOption) SPI() PacketAuthSPI {
	return PacketAuthSPI(binary.BigEndian.Uint32(o.OptData[:4]))
}

// Algorithm returns the algorithm type stored in the data buffer.
func (o PacketAuthOption) Algorithm() PacketAuthAlg {
	return PacketAuthAlg(o.OptData[4])
}

// Timestamp returns the value set in the homonym field in the extension.
func (o PacketAuthOption) Timestamp() uint32 {
	return uint32(o.OptData[5])<<16 + uint32(o.OptData[6])<<8 + uint32(o.OptData[7])
}

// SequenceNumber returns the value set in the homonym field in the extension.
func (o PacketAuthOption) SequenceNumber() uint32 {
	return uint32(o.OptData[9])<<16 + uint32(o.OptData[10])<<8 + uint32(o.OptData[11])
}

// Authenticator returns slice of the underlying auth buffer.
// Changes to this slice will be reflected on the wire when
// the extension is serialized.
func (o PacketAuthOption) Authenticator() []byte {
	return o.OptData[12:]
}

func ComputeAuthCMAC(
	key []byte,
	opt PacketAuthOption,
	scionL *SCION,
	pldType L4ProtocolType,
	pld []byte,
	input []byte,
	macBuffer []byte,
) ([]byte, error) {

	// TODO(matzf): avoid allocations, somehow?
	cmac, err := initCMAC(key)
	if err != nil {
		return nil, err
	}
	inputLen, err := serializeAutenticatedData(input, scionL, opt, pldType, pld)
	if err != nil {
		return nil, err
	}
	cmac.Write(input[:inputLen])
	cmac.Write(pld)
	return cmac.Sum(macBuffer[:0]), nil
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

func serializeAutenticatedData(
	buf []byte,
	s *SCION,
	opt PacketAuthOption,
	pldType L4ProtocolType,
	pld []byte,
) (int, error) {

	buf[0] = byte(CmnHdrLen + s.AddrHdrLen() + s.Path.Len())
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
	buf[17] = byte(s.DstAddrType&0x3)<<6 | byte(s.DstAddrLen&0x3)<<4 |
		byte(s.SrcAddrType&0x3)<<2 | byte(s.SrcAddrLen&0x3)
	binary.BigEndian.PutUint16(buf[18:], 0)
	offset := FixAuthDataInputLen

	if !opt.SPI().IsDRKey() {
		binary.BigEndian.PutUint64(buf[offset:], uint64(s.DstIA))
		binary.BigEndian.PutUint64(buf[offset+8:], uint64(s.SrcIA))
		offset += 16
	}
	if !opt.SPI().IsDRKey() ||
		(opt.SPI().Type() == PacketAuthASHost &&
			opt.SPI().Direction() == PacketAuthReceiverSide) {
		offset += copy(buf[offset:], s.RawDstAddr)
	}
	if !opt.SPI().IsDRKey() ||
		(opt.SPI().Type() == PacketAuthASHost &&
			opt.SPI().Direction() == PacketAuthSenderSide) {
		offset += copy(buf[offset:], s.RawSrcAddr)
	}
	err := zeroOutMutablePath(s.Path, buf[offset:])
	if err != nil {
		return 0, err
	}
	offset += s.Path.Len()
	return offset, nil
}

// ComputeSPAORelativeTimestamp computes the relative timestamp (spaoTS) where:
// now = ts+spaoTS⋅𝑞, (where q := 6 ms and ts =  info[0].Timestamp, i.e.,
// the timestamp field in the first InfoField).
func ComputeSPAORelativeTimestamp(ts uint32, now time.Time) (uint32, error) {
	timestamp := now.Sub(util.SecsToTime(ts)).Milliseconds() / 6
	if timestamp >= (1 << 24) {
		return 0, serrors.New("relative timestamp is bigger than 2^24-1")
	}
	return uint32(timestamp), nil
}

// TimeFromRelativeTimestamp computes the time instant (then) where:
// then = ts + spaoTS⋅𝑞, (where q := 6 ms and ts =  info[0].Timestamp, i.e.,
// the timestamp field in the first InfoField).
func TimeFromRelativeTimestamp(ts uint32, spaoTS uint32) time.Time {
	return util.SecsToTime(ts).Add(time.Millisecond * time.Duration(spaoTS) * 6)
}

func zeroOutMutablePath(orig path.Path, buf []byte) error {
	err := orig.SerializeTo(buf)
	if err != nil {
		return serrors.WrapStr("serializing path for reseting fields", err)
	}
	switch p := orig.(type) {
	// TODO(JordiSubira): process EPIC

	case *scion.Raw:
		zeroOutWithBase(p.Base, 0, buf)
		return nil
	case *scion.Decoded:
		zeroOutWithBase(p.Base, 0, buf)
		return nil
	case *epic.Path:
		zeroOutWithBase(p.ScionPath.Base, epic.MetadataLen, buf)
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

func zeroOutWithBase(base scion.Base, offset int, buf []byte) {
	// Zero out CurrInf && CurrHF
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
