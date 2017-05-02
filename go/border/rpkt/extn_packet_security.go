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
	"github.com/netsec-ethz/scion/go/lib/spse"
)

var _ rExtension = (*rSPSExtn)(nil)

// rSPSBaseExtn is the base for rSPSExtn, rSCMPAuthDRKeyExt and rSCMPAuthHashTreeExt
type rSPSBaseExtn struct {
	rp      *RtrPkt
	raw     common.RawBytes
	start   int
	SecMode uint8
	log.Logger
}

func (s *rSPSBaseExtn) Offset() int {
	return s.start
}

func (s *rSPSBaseExtn) Len() int {
	return len(s.raw)
}

func (s *rSPSBaseExtn) Class() common.L4ProtocolType {
	return common.End2EndClass
}

func (s *rSPSBaseExtn) Type() common.ExtnType {
	return common.ExtnSCIONPacketSecurityType
}

// rSPSExtn is the router's representation of the SCIONPacketSecurity extension.
type rSPSExtn struct {
	*rSPSBaseExtn
}

// rSPSExtFromRaw creates an rSPSExtn instance from raw bytes,
// keeping a reference to the location in the packet's buffer.
func rSPSExtFromRaw(rp *RtrPkt, start, end int) (*rSPSExtn, *common.Error) {
	raw := rp.Raw[start:end]
	mode := raw[0]
	if !spse.IsSupported(mode) {
		return nil, common.NewError("SecMode not supported", "mode", mode)
	}
	s := &rSPSExtn{
		&rSPSBaseExtn{rp: rp, raw: raw, start: start, SecMode: mode}}
	s.Logger = rp.Logger.New("ext", "SCIONPacketSecurity")
	return s, nil
}

// Metadata returns a slice of the underlying buffer
func (s *rSPSExtn) Metadata() (common.RawBytes, *common.Error) {
	l, h, err := s.limitsMetadata()
	if err != nil {
		return nil, err
	}
	return s.raw[l:h], nil
}

// Set the Metadata directly in the underlying buffer.
func (s *rSPSExtn) SetMetadata(metadata common.RawBytes) *common.Error {
	meta, err := s.Metadata()
	if err != nil {
		return err
	}
	if len(meta) != len(metadata) {
		return common.NewError("Invalid metadata length", "len", len(metadata),
			"expected", len(metadata))
	}
	copy(meta, metadata)
	return nil
}

// Authenticator returns a slice of the underlying buffer
func (s *rSPSExtn) Authenticator() (common.RawBytes, *common.Error) {
	l, h, err := s.limitsAuthenticator()
	if err != nil {
		return nil, err
	}
	return s.raw[l:h], nil
}

// Set the Authenticator directly in the underlying buffer.
func (s *rSPSExtn) SetAuthenticator(authenticator common.RawBytes) *common.Error {
	auth, err := s.Authenticator()
	if err != nil {
		return err
	}
	if len(auth) != len(authenticator) {
		return common.NewError("Invalid authenticator length", "len", len(authenticator),
			"expected", len(auth))
	}
	copy(auth, authenticator)
	return nil
}

func (s *rSPSExtn) RegisterHooks(h *hooks) *common.Error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSPSExtn) Validate() (HookResult, *common.Error) {
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

// GetExtn returns the spse.Extn representation,
// which does not have direct access to the underling buffer.
func (s *rSPSExtn) GetExtn() (common.Extension, *common.Error) {
	extn, err := spse.NewExtn(s.SecMode)
	if err != nil {
		return nil, err
	}
	meta, err := s.Metadata()
	if err != nil {
		return nil, err
	}
	auth, err := s.Authenticator()
	if err != nil {
		return nil, err
	}
	extn.SetMetadata(meta)
	extn.SetAuthenticator(auth)
	return extn, nil
}

func (s *rSPSExtn) String() string {
	// Delegate string representation to spse.Extn
	extn, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCIONPacketSecurity - %v: %v", err.Desc, err.String())
	}
	return extn.String()
}

// limits is a helper function to return limits of a slice
func limits(h, byteSize int) (int, int) {
	return h, h + byteSize
}

// limitsMetadata returns the limits of the Metadata in the raw buffer
func (s *rSPSExtn) limitsMetadata() (int, int, *common.Error) {
	switch s.SecMode {
	case spse.AesCMac:
		l, h := limits(spse.SecModeLength, spse.AesCMacMetaLength)
		return l, h, nil
	case spse.HmacSha256:
		l, h := limits(spse.SecModeLength, spse.HmacSha256MetaLength)
		return l, h, nil
	case spse.ED25519:
		l, h := limits(spse.SecModeLength, spse.ED25519MetaLength)
		return l, h, nil
	case spse.GcmAes128:
		l, h := limits(spse.SecModeLength, spse.GcmAes128MetaLength)
		return l, h, nil
	}
	return 0, 0, common.NewError("Invalid SecMode", "mode", s.SecMode,
		"func", "limitsMetadata")
}

// limitsAuthenticator returns the limits of the Authenticator in the raw buffer
func (s *rSPSExtn) limitsAuthenticator() (int, int, *common.Error) {
	switch s.SecMode {
	case spse.AesCMac:
		lower := spse.SecModeLength + spse.AesCMacMetaLength
		upper := spse.AesCMacAuthLength
		l, h := limits(lower, upper)
		return l, h, nil
	case spse.HmacSha256:
		lower := spse.SecModeLength + spse.HmacSha256MetaLength
		upper := spse.HmacSha256AuthLength
		l, h := limits(lower, upper)
		return l, h, nil
	case spse.ED25519:
		lower := spse.SecModeLength + spse.ED25519MetaLength
		upper := spse.ED25519AuthLength
		l, h := limits(lower, upper)
		return l, h, nil
	case spse.GcmAes128:
		lower := spse.SecModeLength + spse.GcmAes128MetaLength
		upper := spse.GcmAes128AuthLength
		l, h := limits(lower, upper)
		return l, h, nil
	}
	return 0, 0, common.NewError("Invalid SecMode", "mode", s.SecMode,
		"func", "limitsAuthenticator")
}
