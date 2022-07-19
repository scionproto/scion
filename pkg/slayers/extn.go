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

package slayers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/pkg/private/serrors"
)

var (
	ErrOptionNotFound = serrors.New("Option not found")
)

// OptionType indicates the type of a TLV Option that is part of an extension header.
type OptionType uint8

// Definition of option type constants.
const (
	OptTypePad1 OptionType = iota
	OptTypePadN
	OptTypeAuthenticator
)

type tlvOption struct {
	OptType      OptionType
	OptDataLen   uint8
	ActualLength int
	OptData      []byte
	OptAlign     [2]uint8 // Xn+Y = [2]uint8{X, Y}
}

func (o *tlvOption) length(fixLengths bool) int {
	if o.OptType == OptTypePad1 {
		return 1
	}
	if fixLengths {
		return len(o.OptData) + 2
	}
	return int(o.OptDataLen) + 2
}

func (o *tlvOption) serializeTo(data []byte, fixLengths bool) {
	dryrun := data == nil
	if o.OptType == OptTypePad1 {
		if !dryrun {
			data[0] = 0x0
		}
		return
	}
	if fixLengths {
		o.OptDataLen = uint8(len(o.OptData))
	}
	if !dryrun {
		data[0] = uint8(o.OptType)
		data[1] = o.OptDataLen
		copy(data[2:], o.OptData)
	}
}

func decodeTLVOption(data []byte) (*tlvOption, error) {
	o := &tlvOption{OptType: OptionType(data[0])}
	if OptionType(data[0]) == OptTypePad1 {
		o.ActualLength = 1
		return o, nil
	}
	if len(data) < 2 {
		return nil, serrors.New("buffer too short", "expected", 2, "actual", len(data))
	}
	o.OptDataLen = data[1]
	o.ActualLength = int(o.OptDataLen) + 2
	if len(data) < o.ActualLength {
		return nil, serrors.New("buffer too short", "expected", o.ActualLength, "actual", len(data))
	}
	o.OptData = data[2:o.ActualLength]
	return o, nil
}

// serializeTLVOptionPadding adds an appropriate PadN extension.
func serializeTLVOptionPadding(data []byte, padLength int) {
	if padLength <= 0 {
		return
	}
	if padLength == 1 {
		data[0] = 0x0
		return
	}
	dataLen := uint8(padLength) - 2
	padN := tlvOption{
		OptType:    OptTypePadN,
		OptDataLen: dataLen,
		OptData:    make([]byte, dataLen),
	}
	padN.serializeTo(data, false)
}

// serializeTLVOptions serializes options to buf and returns the length of the serialized options.
// Passing in a nil-buffer will treat the serialization as a dryrun that can be used to calculate
// the length needed for the buffer.
func serializeTLVOptions(buf []byte, options []*tlvOption, fixLengths bool) int {
	dryrun := buf == nil
	// length start at 2 since the padding needs to be calculated taking the first 2 bytes of the
	// extension header (NextHdr and ExtLen fields) into account.
	length := 2
	for _, opt := range options {
		if fixLengths {
			x := int(opt.OptAlign[0])
			y := int(opt.OptAlign[1])
			if x != 0 {
				n := length / x
				offset := x*n + y
				if offset < length {
					offset += x
				}
				if length != offset {
					pad := offset - length
					if !dryrun {
						serializeTLVOptionPadding(buf[length-2:], pad)
					}
					length += pad
				}
			}
		}
		if !dryrun {
			opt.serializeTo(buf[length-2:], fixLengths)
		}
		length += opt.length(fixLengths)
	}
	if fixLengths {
		p := length % LineLen
		if p != 0 {
			pad := LineLen - p
			if !dryrun {
				serializeTLVOptionPadding(buf[length-2:], pad)
			}
			length += pad
		}
	}
	return length - 2
}

type extnBase struct {
	BaseLayer
	NextHdr L4ProtocolType
	// ExtLen is the length of the extension header in multiple of 4-bytes NOT including the
	// first 4 bytes.
	ExtLen    uint8
	ActualLen int
}

func (e *extnBase) serializeToWithTLVOptions(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions, tlvOptions []*tlvOption) error {

	l := serializeTLVOptions(nil, tlvOptions, opts.FixLengths)
	bytes, err := b.PrependBytes(l)
	if err != nil {
		return err
	}
	serializeTLVOptions(bytes, tlvOptions, opts.FixLengths)

	length := len(bytes) + 2
	if length%LineLen != 0 {
		return serrors.New("SCION extension actual length must be multiple of 4")
	}
	bytes, err = b.PrependBytes(2)
	if err != nil {
		return err
	}
	bytes[0] = uint8(e.NextHdr)
	if opts.FixLengths {
		e.ExtLen = uint8((length / LineLen) - 1)
	}
	bytes[1] = e.ExtLen
	return nil
}

func decodeExtnBase(data []byte, df gopacket.DecodeFeedback) (extnBase, error) {
	e := extnBase{}
	if len(data) < 2 {
		df.SetTruncated()
		return e, serrors.New(fmt.Sprintf("invalid extension header. Length %d less than 2",
			len(data)))
	}
	e.NextHdr = L4ProtocolType(data[0])
	e.ExtLen = data[1]
	e.ActualLen = (int(e.ExtLen) + 1) * LineLen
	if len(data) < e.ActualLen {
		return extnBase{}, serrors.New(fmt.Sprintf("invalid extension header. "+
			"Length %d less than specified length %d", len(data), e.ActualLen))
	}
	e.Contents = data[:e.ActualLen]
	e.Payload = data[e.ActualLen:]
	return e, nil
}

// HopByHopOption is a TLV option present in a SCION hop-by-hop extension.
type HopByHopOption tlvOption

// HopByHopExtn is the SCION hop-by-hop options extension.
type HopByHopExtn struct {
	extnBase
	Options []*HopByHopOption
}

func (h *HopByHopExtn) LayerType() gopacket.LayerType {
	return LayerTypeHopByHopExtn
}

func (h *HopByHopExtn) CanDecode() gopacket.LayerClass {
	return LayerClassHopByHopExtn
}

func (h *HopByHopExtn) NextLayerType() gopacket.LayerType {
	return scionNextLayerTypeAfterHBH(h.NextHdr)
}

func (h *HopByHopExtn) LayerPayload() []byte {
	return h.Payload
}

// SerializeTo implementation according to gopacket.SerializableLayer.
func (h *HopByHopExtn) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	if err := checkHopByHopExtnNextHdr(h.NextHdr); err != nil {
		return err
	}

	o := make([]*tlvOption, 0, len(h.Options))
	for _, v := range h.Options {
		o = append(o, (*tlvOption)(v))
	}

	return h.extnBase.serializeToWithTLVOptions(b, opts, o)
}

// DecodeFromBytes implementation according to gopacket.DecodingLayer.
func (h *HopByHopExtn) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var err error
	h.extnBase, err = decodeExtnBase(data, df)
	if err != nil {
		return err
	}
	if err := checkHopByHopExtnNextHdr(h.NextHdr); err != nil {
		return err
	}
	offset := 2
	for offset < h.ActualLen {
		opt, err := decodeTLVOption(data[offset:h.ActualLen])
		if err != nil {
			return err
		}
		h.Options = append(h.Options, (*HopByHopOption)(opt))
		offset += opt.ActualLength
	}
	return nil
}

func decodeHopByHopExtn(data []byte, p gopacket.PacketBuilder) error {
	h := &HopByHopExtn{}
	err := h.DecodeFromBytes(data, p)
	p.AddLayer(h)
	if err != nil {
		return err
	}
	return p.NextDecoder(scionNextLayerTypeAfterHBH(h.NextHdr))
}

func checkHopByHopExtnNextHdr(t L4ProtocolType) error {
	if t == HopByHopClass {
		return serrors.New("hbh extension must not be repeated")
	}
	return nil
}

// EndToEndOption is a TLV option present in a SCION end-to-end extension.
type EndToEndOption tlvOption

// EndToEndExtn is the SCION end-to-end options extension.
type EndToEndExtn struct {
	extnBase
	Options []*EndToEndOption
}

func (e *EndToEndExtn) LayerType() gopacket.LayerType {
	return LayerTypeEndToEndExtn
}

func (e *EndToEndExtn) CanDecode() gopacket.LayerClass {
	return LayerClassEndToEndExtn
}

func (e *EndToEndExtn) NextLayerType() gopacket.LayerType {
	return scionNextLayerTypeAfterE2E(e.NextHdr)
}

func (e *EndToEndExtn) LayerPayload() []byte {
	return e.Payload
}

// DecodeFromBytes implementation according to gopacket.DecodingLayer.
func (e *EndToEndExtn) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var err error
	e.extnBase, err = decodeExtnBase(data, df)
	if err != nil {
		return err
	}
	if err := checkEndToEndExtnNextHdr(e.NextHdr); err != nil {
		return err
	}
	offset := 2
	for offset < e.ActualLen {
		opt, err := decodeTLVOption(data[offset:e.ActualLen])
		if err != nil {
			return err
		}
		e.Options = append(e.Options, (*EndToEndOption)(opt))
		offset += opt.ActualLength
	}
	return nil
}

func decodeEndToEndExtn(data []byte, p gopacket.PacketBuilder) error {
	e := &EndToEndExtn{}
	err := e.DecodeFromBytes(data, p)
	p.AddLayer(e)
	if err != nil {
		return err
	}
	return p.NextDecoder(scionNextLayerTypeAfterE2E(e.NextHdr))
}

func checkEndToEndExtnNextHdr(t L4ProtocolType) error {
	if t == HopByHopClass {
		return serrors.New("e2e extension must not come before the HBH extension")
	} else if t == End2EndClass {
		return serrors.New("e2e extension must not be repeated")
	}
	return nil
}

// SerializeTo implementation according to gopacket.SerializableLayer
func (e *EndToEndExtn) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	if err := checkEndToEndExtnNextHdr(e.NextHdr); err != nil {
		return err
	}

	o := make([]*tlvOption, 0, len(e.Options))
	for _, v := range e.Options {
		o = append(o, (*tlvOption)(v))
	}

	return e.extnBase.serializeToWithTLVOptions(b, opts, o)
}

// FindOption returns the first option entry of the given type if any exists,
// or ErrOptionNotFound otherwise.
func (e *EndToEndExtn) FindOption(typ OptionType) (*EndToEndOption, error) {
	for _, o := range e.Options {
		if o.OptType == typ {
			return o, nil
		}
	}
	return nil, ErrOptionNotFound
}

// HopByHopExtnSkipper is a DecodingLayer which decodes a HopByHop extension
// without parsing its content.
// This can be used with a DecodingLayerParser to handle SCION packets which
// may or may not have a HopByHop extension.
type HopByHopExtnSkipper struct {
	extnBase
}

// DecodeFromBytes implementation according to gopacket.DecodingLayer
func (s *HopByHopExtnSkipper) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var err error
	s.extnBase, err = decodeExtnBase(data, df)
	if err != nil {
		return err
	}
	if err := checkHopByHopExtnNextHdr(s.NextHdr); err != nil {
		return err
	}
	return nil
}

func (e *HopByHopExtnSkipper) LayerType() gopacket.LayerType {
	return LayerTypeHopByHopExtn
}

func (s *HopByHopExtnSkipper) CanDecode() gopacket.LayerClass {
	return LayerClassHopByHopExtn
}

func (h *HopByHopExtnSkipper) NextLayerType() gopacket.LayerType {
	return scionNextLayerTypeAfterHBH(h.NextHdr)
}

// EndToEndExtnSkipper is a DecodingLayer which decodes a HopByHop extensions
// without parsing its content.
// This can be used with a DecodingLayerParser to handle SCION packets which
// may or may not have an EndToEnd extension.
type EndToEndExtnSkipper struct {
	extnBase
}

// DecodeFromBytes implementation according to gopacket.DecodingLayer
func (s *EndToEndExtnSkipper) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var err error
	s.extnBase, err = decodeExtnBase(data, df)
	if err != nil {
		return err
	}
	if err := checkEndToEndExtnNextHdr(s.NextHdr); err != nil {
		return err
	}
	return nil
}

func (e *EndToEndExtnSkipper) LayerType() gopacket.LayerType {
	return LayerTypeEndToEndExtn
}

func (s *EndToEndExtnSkipper) CanDecode() gopacket.LayerClass {
	return LayerClassEndToEndExtn
}

func (e *EndToEndExtnSkipper) NextLayerType() gopacket.LayerType {
	return scionNextLayerTypeAfterE2E(e.NextHdr)
}

// PacketAuthSPI is the identifier for the key used for the
// packet authentication option. DRKey values are in the
// range [1, 2^21-1].
type PacketAuthSPI uint32

type PacketAuthDRKeyType uint8

const (
	PacketAuthASHost PacketAuthDRKeyType = iota
	PacketAuthHostHost
)

type PacketAuthDRKeyDirection uint8

const (
	PacketAuthSenderSide PacketAuthDRKeyDirection = iota
	PacketAuthReceiverSide
)

type PacketAuthDRKeyEpochType uint8

const (
	PacketAuthLater PacketAuthDRKeyEpochType = iota
	PacketAuthEarlier
)

func (p PacketAuthSPI) Type() PacketAuthDRKeyType {
	if p&(1<<18) == 0 {
		return PacketAuthASHost
	}
	return PacketAuthHostHost
}

func (p PacketAuthSPI) Direction() PacketAuthDRKeyDirection {
	if p&(1<<17) == 0 {
		return PacketAuthSenderSide
	}
	return PacketAuthReceiverSide
}

func (p PacketAuthSPI) Epoch() PacketAuthDRKeyEpochType {
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
	drkeyType PacketAuthDRKeyType,
	dir PacketAuthDRKeyDirection,
	epoch PacketAuthDRKeyEpochType,
) PacketAuthSPI {

	if proto < 1 {
		panic("Invalid proto identifier value")
	}
	if drkeyType > 1 {
		panic("Invalid DRKeyType value")
	}
	if dir > 1 {
		panic("Invalid DRKeyDirection value")
	}
	if epoch > 1 {
		panic("Invalid DRKeyEpochType value")
	}
	spi := uint32((drkeyType & 0x1)) << 18
	spi |= uint32((dir & 0x1)) << 17
	spi |= uint32((epoch & 0x1)) << 16
	spi |= uint32(proto)

	return PacketAuthSPI(spi)
}

// PacketAuthAlg is the enumerator for authenticator algorithm types in the
// packet authenticator option.
type PacketAuthAlg uint8

const (
	PacketAuthCMAC PacketAuthAlg = iota
	PacketAuthSHA1_AES_CBC
)

// PacketAuthOption wraps an EndToEndOption of OptTypeAuthenticator.
// This can be used to serialize and parse the internal structure of the packet authenticator
// option.
type PacketAuthOption struct {
	*EndToEndOption
}

// NewPacketAuthOption creates a new EndToEndOption of
// OptTypeAuthenticator, initialized with the given SPAO data.
func NewPacketAuthOption(
	spi PacketAuthSPI,
	alg PacketAuthAlg,
	ts uint32,
	sn uint32,
	auth []byte,
) PacketAuthOption {

	o := PacketAuthOption{EndToEndOption: new(EndToEndOption)}
	o.Reset(spi, alg, ts, sn, auth)
	return o
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
	if len(o.OptData) < 12 {
		return PacketAuthOption{},
			serrors.New("buffer too short", "expected", 12, "actual", len(o.OptData))
	}
	return PacketAuthOption{o}, nil
}

// Reset reinitializes the underlying EndToEndOption with the SPAO data.
// Reuses the OptData buffer if it is of sufficient capacity.
func (o PacketAuthOption) Reset(
	spi PacketAuthSPI,
	alg PacketAuthAlg,
	ts uint32,
	sn uint32,
	auth []byte,
) {

	if ts >= (1 << 24) {
		panic("Timestamp value should be smaller than 2^24")
	}
	if sn >= (1 << 24) {
		panic("Sequence number should be smaller than 2^24")
	}

	o.OptType = OptTypeAuthenticator

	n := 12 + len(auth) // 4 + 1 + 3 + 1 + 3 + len(data)
	if n <= cap(o.OptData) {
		o.OptData = o.OptData[:n]
	} else {
		o.OptData = make([]byte, n)
	}
	binary.BigEndian.PutUint32(o.OptData[:4], uint32(spi))
	o.OptData[4] = byte(alg)
	o.OptData[5] = byte(ts >> 16)
	o.OptData[6] = byte(ts >> 8)
	o.OptData[7] = byte(ts)
	o.OptData[8] = byte(0)
	o.OptData[9] = byte(sn >> 16)
	o.OptData[10] = byte(sn >> 8)
	o.OptData[11] = byte(sn)
	copy(o.OptData[12:], auth)

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
}

// SPI returns returns the value set in the homonym field in the extension.
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
