// Copyright 2017 ETH Zurich
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

// This file contains the router's representation of the end-to-end SCION
// Packet Security extension.

package rpkt

import (
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn"
)

var _ rExtension = (*rSCIONPacketSecurityExt)(nil)

// rSCIONPacketSecurityBaseExt is the base for
// rSCIONPacketSecurityExt, rSCMPAuthDRKeyExt and rSCMPAuthHashTreeExt
type rSCIONPacketSecurityBaseExt struct {
	rp      *RtrPkt
	raw     common.RawBytes
	start   int
	SecMode uint8
	log.Logger
}

func (s *rSCIONPacketSecurityBaseExt) Offset() int {
	return s.start
}

func (s *rSCIONPacketSecurityBaseExt) Len() int {
	return len(s.raw)
}

func (s *rSCIONPacketSecurityBaseExt) Class() common.L4ProtocolType {
	return common.End2EndClass
}

func (s *rSCIONPacketSecurityBaseExt) Type() common.ExtnType {
	return common.ExtnSCIONPacketSecurityType
}

func (s *rSCIONPacketSecurityExt) String() string {
	// Delegate string representation to sps.Extn
	extn, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCIONPacketSecurity - %v: %v", err.Desc, err.String())
	}
	return extn.String()
}

// rSCIONPacketSecurityExt is the router's representation of the
// SCIONPacketSecurity extension.
type rSCIONPacketSecurityExt struct {
	*rSCIONPacketSecurityBaseExt
}

// rSCIONPacketSecurityExtFromRaw creates an rSecurityExt instance from raw bytes,
// keeping a reference to the location in the packet's buffer.
func rSCIONPacketSecurityExtFromRaw(rp *RtrPkt, start, end int) (*rSCIONPacketSecurityExt, *common.Error) {
	raw := rp.Raw[start:end]
	mode := raw[0]
	if !spse.IsSupported(mode) {
		return nil, common.NewError("SecMode not supported", "mode", mode)
	}
	s := &rSCIONPacketSecurityExt{
		&rSCIONPacketSecurityBaseExt{rp: rp, raw: raw, start: start, SecMode: mode}}
	s.Logger = rp.Logger.New("ext", "SCIONPacketSecurity")
	return s, nil
}

// Metadata returns a slice of the underlying buffer
func (s *rSCIONPacketSecurityExt) Metadata() common.RawBytes {
	l, h := s.limitsMetadata()
	return s.raw[l:h]
}

// Set the Metadata directly in the underlying buffer.
func (s *rSCIONPacketSecurityExt) SetMetadata(metadata common.RawBytes) *common.Error {
	if len(s.Metadata()) != len(metadata) {
		return common.NewError("Invalid metadata length", "len", len(metadata),
			"expected", len(s.Metadata()))
	}
	copy(s.Metadata(), metadata)
	return nil
}

// Authenticator returns a slice of the underlying buffer
func (s *rSCIONPacketSecurityExt) Authenticator() common.RawBytes {
	l, h := s.limitsAuthenticator()
	return s.raw[l:h]
}

// Set the Authenticator directly in the underlying buffer.
func (s *rSCIONPacketSecurityExt) SetAuthenticator(authenticator common.RawBytes) *common.Error {
	if len(s.Authenticator()) != len(authenticator) {
		return common.NewError("Invalid authenticator length", "len", len(authenticator),
			"expected", len(s.Authenticator()))
	}
	copy(s.Authenticator(), authenticator)
	return nil
}

func (s *rSCIONPacketSecurityExt) RegisterHooks(h *hooks) *common.Error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSCIONPacketSecurityExt) Validate() (HookResult, *common.Error) {
	notMatchingLen := false
	expectedLen := 0
	switch {
	case spse.AesCMac == s.SecMode:
		expectedLen = spse.AesCMacTotalLength
		notMatchingLen = (len(s.raw) != expectedLen)
	case spse.HmacSha256 == s.SecMode:
		expectedLen = spse.HmacSha256TotalLength
		notMatchingLen = (len(s.raw) != expectedLen)
	case spse.ED25519 == s.SecMode:
		expectedLen = spse.ED25519TotalLength
		notMatchingLen = (len(s.raw) != expectedLen)
	case spse.GcmAes128 == s.SecMode:
		expectedLen = spse.GcmAes128TotalLength
		notMatchingLen = (len(s.raw) != expectedLen)
	default:
		return HookError, common.NewError("SecMode not supported", "mode", s.SecMode)
	}

	if notMatchingLen {
		return HookError, common.NewError("Invalid header length", "len", len(s.raw),
			"expected", expectedLen)
	}

	return HookContinue, nil
}

// GetExtn returns the spkt.Security representation,
// which does not have direct access to the underling buffer.
func (s *rSCIONPacketSecurityExt) GetExtn() (common.Extension, *common.Error) {
	extn, err := spse.NewSCIONPacketSecurityExtn(s.SecMode)
	if err != nil {
		return nil, err
	}
	extn.SetMetadata(s.Metadata())
	extn.SetAuthenticator(s.Authenticator())
	return extn, nil
}

// limits is a helper function to return limits of a slice
func limits(h, byteSize int) (int, int) {
	return h, h + byteSize
}

// limitsMetadata returns the limits of the Metadata in the raw buffer
func (s *rSCIONPacketSecurityExt) limitsMetadata() (int, int) {
	switch s.SecMode {
	case spse.AesCMac:
		return limits(spse.SecModeLength, spse.AesCMacMetaLength)
	case spse.HmacSha256:
		return limits(spse.SecModeLength, spse.HmacSha256MetaLength)
	case spse.ED25519:
		return limits(spse.SecModeLength, spse.ED25519MetaLength)
	case spse.GcmAes128:
		return limits(spse.SecModeLength, spse.GcmAes128MetaLength)
	}
	s.Warn("Unreachable code reached. SecMode has been altered",
		"func", "limitsMetadata", "SecMode", s.SecMode)
	return 0, 0
}

// limitsAuthenticator returns the limits of the Authenticator in the raw buffer
func (s *rSCIONPacketSecurityExt) limitsAuthenticator() (int, int) {
	switch s.SecMode {
	case spse.AesCMac:
		lower := spse.SecModeLength + spse.AesCMacMetaLength
		upper := spse.AesCMacAuthLength
		return limits(lower, upper)
	case spse.HmacSha256:
		lower := spse.SecModeLength + spse.HmacSha256MetaLength
		upper := spse.HmacSha256AuthLength
		return limits(lower, upper)
	case spse.ED25519:
		lower := spse.SecModeLength + spse.ED25519MetaLength
		upper := spse.ED25519AuthLength
		return limits(lower, upper)
	case spse.GcmAes128:
		lower := spse.SecModeLength + spse.GcmAes128MetaLength
		upper := spse.GcmAes128AuthLength
		return limits(lower, upper)
	}
	s.Warn("Unreachable code reached. SecMode has been altered",
		"func", "limitsAuthenticator", "SecMode", s.SecMode)
	return 0, 0
}
