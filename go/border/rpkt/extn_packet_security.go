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
// rSCIONPacketSecurityExt, rSCMPAuthDRKeyExt and
type rSCIONPacketSecurityBaseExt struct {
	rp      *RtrPkt
	raw     common.RawBytes
	start   int
	SecMode uint8
	log.Logger
}

// rSCIONPacketSecurityExt is the router's representation of the
// SCIONPacketSecurity extension.
type rSCIONPacketSecurityExt struct {
	*rSCIONPacketSecurityBaseExt
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
	// Delegate string representation to spkt.SCIONPacketSecurityExtn
	e, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCIONPacketSecurity - %v: %v", err.Desc, err.String())
	}
	return e.String()
}

// rSCIONPacketSecurityExtFromRaw creates an rSecurityExt instance from raw bytes,
// keeping a reference to the location in the packet's buffer.
func rSCIONPacketSecurityExtFromRaw(rp *RtrPkt, start, end int) (*rSCIONPacketSecurityExt, *common.Error) {
	raw := rp.Raw[start:end]
	mode := raw[0]
	if !pkt_sec_extn.IsSupported(mode) {
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

// Update the Metadata directly in the underlying buffer.
func (s *rSCIONPacketSecurityExt) UpdateMetadata(metadata common.RawBytes) *common.Error{
	if len(s.Metadata()) != len(metadata) {
		return common.NewError("Invalid metadata length", "len", len(metadata))
	}
	copy(s.Metadata(), metadata)
	return nil
}

// Authenticator returns a slice of the underlying buffer
func (s *rSCIONPacketSecurityExt) Authenticator() common.RawBytes {
	l, h := s.limitsAuthenticator()
	return s.raw[l:h]
}

// Update the Authenticator directly in the underlying buffer.
func (s *rSCIONPacketSecurityExt) UpdateAuthenticator(authenticator common.RawBytes) *common.Error {
	if len(s.Authenticator()) != len(authenticator) {
		return common.NewError("Invalid authenticator length", "len", len(authenticator))
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
	switch {
	case pkt_sec_extn.AES_CMAC == s.SecMode:
		notMatchingLen = (len(s.raw) != pkt_sec_extn.AES_CMAC_TOTAL_LENGTH)
	case pkt_sec_extn.HMAC_SHA256 == s.SecMode:
		notMatchingLen = (len(s.raw) != pkt_sec_extn.HMAC_SHA256_TOTAL_LENGTH)
	case pkt_sec_extn.ED25519 == s.SecMode:
		notMatchingLen = (len(s.raw) != pkt_sec_extn.ED25519_TOTAL_LENGTH)
	case pkt_sec_extn.GCM_AES128 == s.SecMode:
		notMatchingLen = (len(s.raw) != pkt_sec_extn.GCM_AES128_TOTAL_LENGTH)
	default:
		return HookError, common.NewError("SecMode not supported", "mode", s.SecMode)
	}

	if notMatchingLen {
		return HookError, common.NewError("Invalid header length", "len", len(s.raw))
	}

	return HookContinue, nil
}

// GetExtn returns the spkt.Security representation,
// which does not have direct access to the underling buffer.
func (s *rSCIONPacketSecurityExt) GetExtn() (common.Extension, *common.Error) {
	c, e := pkt_sec_extn.NewSCIONPacketSecurityExtn(s.SecMode)
	if e != nil {
		return nil, e
	}
	c.UpdateMetadata(s.Metadata())
	c.UpdateAuthenticator(s.Authenticator())
	return c, nil
}

// limits is a helper function to return limits of a slice
func limits(h, byteSize int) (int, int) {
	return h, h + byteSize
}

// limitsMetadata returns the limits of the Metadata in the raw buffer
func (s *rSCIONPacketSecurityExt) limitsMetadata() (int, int) {
	switch s.SecMode {
	case pkt_sec_extn.AES_CMAC:
		return limits(pkt_sec_extn.SECMODE_LENGTH, pkt_sec_extn.AES_CMAC_META_LENGTH)
	case pkt_sec_extn.HMAC_SHA256:
		return limits(pkt_sec_extn.SECMODE_LENGTH, pkt_sec_extn.HMAC_SHA256_META_LENGTH)
	case pkt_sec_extn.ED25519:
		return limits(pkt_sec_extn.SECMODE_LENGTH, pkt_sec_extn.ED25519_META_LENGTH)
	case pkt_sec_extn.GCM_AES128:
		return limits(pkt_sec_extn.SECMODE_LENGTH, pkt_sec_extn.GCM_AES128_META_LENGTH)
	}
	s.Warn("Unreachable code reached.")
	return 0, 0
}

// limitsAuthenticator returns the limits of the Authenticator in the raw buffer
func (s *rSCIONPacketSecurityExt) limitsAuthenticator() (int, int) {
	switch s.SecMode {
	case pkt_sec_extn.AES_CMAC:
		return limits(pkt_sec_extn.SECMODE_LENGTH+pkt_sec_extn.AES_CMAC_META_LENGTH,
			pkt_sec_extn.AES_CMAC_AUTH_LENGTH)
	case pkt_sec_extn.HMAC_SHA256:
		return limits(pkt_sec_extn.SECMODE_LENGTH+pkt_sec_extn.HMAC_SHA256_META_LENGTH,
			pkt_sec_extn.HMAC_SHA256_AUTH_LENGTH)
	case pkt_sec_extn.ED25519:
		return limits(pkt_sec_extn.SECMODE_LENGTH+pkt_sec_extn.ED25519_META_LENGTH,
			pkt_sec_extn.ED25519_AUTH_LENGTH)
	case pkt_sec_extn.GCM_AES128:
		return limits(pkt_sec_extn.SECMODE_LENGTH+pkt_sec_extn.GCM_AES128_META_LENGTH,
			pkt_sec_extn.GCM_AES128_AUTH_LENGTH)
	}
	s.Warn("Unreachable code reached.")
	return 0, 0
}
