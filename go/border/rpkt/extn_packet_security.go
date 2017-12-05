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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spse"
)

// rSPSBaseExtn is the base for rSPSExtn, rSCMPAuthDRKeyExtn and rSCMPAuthHashTreeExtn
type rSPSBaseExtn struct {
	rp      *RtrPkt
	raw     common.RawBytes
	SecMode spse.SecMode
	log.Logger
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

func parseSPSEfromRaw(rp *RtrPkt, start, end, pos int) (rExtension, error) {
	secMode := spse.SecMode(rp.Raw[start])
	switch secMode {
	case spse.AesCMac, spse.HmacSha256, spse.Ed25519, spse.GcmAes128:
		return rSPSExtFromRaw(rp, start, end)
	case spse.ScmpAuthDRKey:
		return rSCMPAuthDRKeyExtnFromRaw(rp, start, end)
	case spse.ScmpAuthHashTree:
		return rSCMPAuthHashTreeExtnFromRaw(rp, start, end)
	default:
		sdata := scmp.NewErrData(scmp.C_Ext, scmp.T_E_BadEnd2End,
			&scmp.InfoExtIdx{Idx: uint8(pos)})
		return nil, common.NewCErrorData("Unsupported SecMode", sdata, "mode", secMode)
	}
}

var _ rExtension = (*rSPSExtn)(nil)

// rSPSExtn is the router's representation of the SCIONPacketSecurity extension.
type rSPSExtn struct {
	*rSPSBaseExtn
}

// rSPSExtFromRaw creates an rSPSExtn instance from raw bytes,
// keeping a reference to the location in the packet's buffer.
func rSPSExtFromRaw(rp *RtrPkt, start, end int) (*rSPSExtn, error) {
	raw := rp.Raw[start:end]
	mode := spse.SecMode(raw[0])
	s := &rSPSExtn{&rSPSBaseExtn{rp: rp, raw: raw, SecMode: mode}}
	s.Logger = rp.Logger.New("ext", "SCIONPacketSecurity")
	return s, nil
}

// Metadata returns a slice of the underlying buffer
func (s *rSPSExtn) Metadata() (common.RawBytes, error) {
	l, h, err := s.limitsMetadata()
	if err != nil {
		return nil, err
	}
	return s.raw[l:h], nil
}

// Set the Metadata directly in the underlying buffer.
func (s *rSPSExtn) SetMetadata(metadata common.RawBytes) error {
	meta, err := s.Metadata()
	if err != nil {
		return err
	}
	if len(meta) != len(metadata) {
		return common.NewCError("Invalid metadata length", "expected", len(meta),
			"actual", len(metadata))
	}
	copy(meta, metadata)
	return nil
}

// Authenticator returns a slice of the underlying buffer
func (s *rSPSExtn) Authenticator() (common.RawBytes, error) {
	l, h, err := s.limitsAuthenticator()
	if err != nil {
		return nil, err
	}
	return s.raw[l:h], nil
}

// Set the Authenticator directly in the underlying buffer.
func (s *rSPSExtn) SetAuthenticator(authenticator common.RawBytes) error {
	auth, err := s.Authenticator()
	if err != nil {
		return err
	}
	if len(auth) != len(authenticator) {
		return common.NewCError("Invalid authenticator length", "expected", len(auth),
			"actual", len(authenticator))
	}
	copy(auth, authenticator)
	return nil
}

func (s *rSPSExtn) RegisterHooks(h *hooks) error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSPSExtn) Validate() (HookResult, error) {
	expectedLen := 0
	switch {
	case spse.AesCMac == s.SecMode:
		expectedLen = spse.AesCMacTotalLength
	case spse.HmacSha256 == s.SecMode:
		expectedLen = spse.HmacSha256TotalLength
	case spse.Ed25519 == s.SecMode:
		expectedLen = spse.ED25519TotalLength
	case spse.GcmAes128 == s.SecMode:
		expectedLen = spse.GcmAes128TotalLength
	default:
		return HookError, common.NewCError("SecMode not supported", "mode", s.SecMode)
	}

	if len(s.raw) != expectedLen {
		return HookError, common.NewCError("Invalid header length", "expected", expectedLen,
			"actual", len(s.raw))
	}

	return HookContinue, nil
}

// GetExtn returns the spse.Extn representation,
// which does not have direct access to the underlying buffer.
func (s *rSPSExtn) GetExtn() (common.Extension, error) {
	extn, err := spse.NewExtn(s.SecMode)
	if err != nil {
		return nil, err
	}
	meta, err := s.Metadata()
	if err != nil {
		return nil, err
	}
	extn.SetMetadata(meta)
	auth, err := s.Authenticator()
	if err != nil {
		return nil, err
	}
	extn.SetAuthenticator(auth)
	return extn, nil
}

func (s *rSPSExtn) String() string {
	// Delegate string representation to spse.Extn
	extn, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCIONPacketSecurity - %v", err)
	}
	return extn.String()
}

// limitsMetadata returns the limits of the Metadata in the raw buffer
func (s *rSPSExtn) limitsMetadata() (int, int, error) {
	size := 0
	switch s.SecMode {
	case spse.AesCMac:
		size = spse.AesCMacMetaLength
	case spse.HmacSha256:
		size = spse.HmacSha256MetaLength
	case spse.Ed25519:
		size = spse.ED25519MetaLength
	case spse.GcmAes128:
		size = spse.GcmAes128MetaLength
	default:
		return 0, 0, common.NewCError("Invalid SecMode", "mode", s.SecMode,
			"func", "limitsMetadata")
	}
	return spse.SecModeLength, spse.SecModeLength + size, nil

}

// limitsAuthenticator returns the limits of the Authenticator in the raw buffer
func (s *rSPSExtn) limitsAuthenticator() (int, int, error) {
	size := 0
	switch s.SecMode {
	case spse.AesCMac:
		size = spse.AesCMacAuthLength
	case spse.HmacSha256:
		size = spse.HmacSha256AuthLength
	case spse.Ed25519:
		size = spse.ED25519AuthLength
	case spse.GcmAes128:
		size = spse.GcmAes128AuthLength
	default:
		return 0, 0, common.NewCError("Invalid SecMode", "mode", s.SecMode,
			"func", "limitsAuthenticator")
	}
	_, l, _ := s.limitsMetadata()
	return l, l + size, nil
}
