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

// This file contains the router's representation of the end-2-end SCION
// Packet Security extension.

package rpkt

import (
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn/scmp_auth_extn"
)

var _ rExtension = (*rSCIONPacketSecurityExt)(nil)

// rSCMPAuthExt is the router's representation of the SCMPAuth extension.
type rSCIONPacketSecurityExt struct {
	rp      *RtrPkt
	raw     common.RawBytes
	start   int
	SecMode uint8
	log.Logger
}

// rSecurityExtFromRaw creates an rSecurityExt instance from raw bytes, keeping a
// reference to the location in the packet's buffer.
func rSecurityExtFromRaw(rp *RtrPkt, start, end int) (*rSCIONPacketSecurityExt, *common.Error) {
	s := &rSCIONPacketSecurityExt{rp: rp, raw: rp.Raw[start:end]}
	s.start = start
	s.SecMode = s.raw[0]
	s.Logger = rp.Logger.New("ext", "security")
	return s, nil
}

// Metadata returns a slice of the underlying buffer
func (s *rSCIONPacketSecurityExt) Metadata() common.RawBytes {
	l, h := limitsMetadata(s.SecMode)
	return s.raw[l:h]
}

// Update the Metadata directly in the underlying buffer.
func (s *rSCIONPacketSecurityExt) UpdateMetadata(metadata common.RawBytes) {
	slice := s.Metadata()
	copy(slice, metadata)
}

// Authenticator returns a slice of the underlying buffer
func (s *rSCIONPacketSecurityExt) Authenticator() common.RawBytes {
	l, h := limitsAuthenticator(s.SecMode, len(s.raw))
	return s.raw[l:h]
}

// Update the Authenticator directly in the underlying buffer.
func (s *rSCIONPacketSecurityExt) UpdateAuthenticator(authenticator common.RawBytes) *common.Error {
	slice := s.Authenticator()
	copy(slice, authenticator)
	return nil
}

func (s *rSCIONPacketSecurityExt) RegisterHooks(h *hooks) *common.Error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSCIONPacketSecurityExt) Validate() (HookResult, *common.Error) {
	// Check valid SecMode code
	if s.SecMode > pkt_sec_extn.SCMP_AUTH_HASH_TREE {
		return HookError, common.NewError("SecMode not supported", "code", s.SecMode)
	}

	// Check valid lengths. Can be optimized by ori-ing instead of switching
	notMatchingLen := false
	switch {
	case pkt_sec_extn.AES_CMAC == s.SecMode && (len(s.raw) != pkt_sec_extn.AES_CMAC_TOTAL_LENGTH):
		notMatchingLen = true
	case pkt_sec_extn.HMAC_SHA256 == s.SecMode && (len(s.raw) != pkt_sec_extn.HMAC_SHA256_TOTAL_LENGTH):
		notMatchingLen = true
	case pkt_sec_extn.ED25519 == s.SecMode && (len(s.raw) != pkt_sec_extn.ED25519_TOTAL_LENGTH):
		notMatchingLen = true
	case pkt_sec_extn.GCM_AES128 == s.SecMode && (len(s.raw) != pkt_sec_extn.GCM_AES128_TOTAL_LENGTH):
		notMatchingLen = true
	case pkt_sec_extn.SCMP_AUTH_DRKEY == s.SecMode && (len(s.raw) != scmp_auth_extn.DRKEY_TOTAL_LENGTH):
		notMatchingLen = true
	case pkt_sec_extn.SCMP_AUTH_HASH_TREE == s.SecMode && (len(s.raw) != hashTreeTotalLength(hashTreeHeight(s.raw))):
		notMatchingLen = true
	}

	if notMatchingLen {
		return HookError, common.NewError("Header length does not match the definition", "len", len(s.raw))
	}

	return HookContinue, nil
}

// GetExtn returns the spkt.Security representation,
// which does not have direct access to the underling buffer.
func (r *rSCIONPacketSecurityExt) GetExtn() (common.Extension, *common.Error) {
	var s common.Extension
	var e *common.Error

	if r.SecMode == pkt_sec_extn.SCMP_AUTH_DRKEY {
		s, e = scmp_auth_extn.NewSCMPDRKeyAuthExtn(r.SecMode)
		if e != nil {
			return nil, e
		}
		s.(*scmp_auth_extn.SCMPAuthExtn).UpdateMetadata(r.Metadata())
		s.(*scmp_auth_extn.SCMPAuthExtn).UpdateAuthenticator(r.Authenticator())
	} else if r.SecMode == pkt_sec_extn.SCMP_AUTH_HASH_TREE {
		s, e = scmp_auth_extn.NewSCMPHashedTreeExtn(r.SecMode, hashTreeHeight(r.raw))
		if e != nil {
			return nil, e
		}
		s.(*scmp_auth_extn.SCMPAuthExtn).UpdateMetadata(r.Metadata())
		s.(*scmp_auth_extn.SCMPAuthExtn).UpdateAuthenticator(r.Authenticator())
	} else {
		s, e = pkt_sec_extn.NewSecurityExtn(r.SecMode)
		if e != nil {
			return nil, e
		}
		s.(*pkt_sec_extn.SCIONPacketSecurityExtn).UpdateMetadata(r.Metadata())
		s.(*pkt_sec_extn.SCIONPacketSecurityExtn).UpdateAuthenticator(r.Authenticator())
	}
	return s, nil
}

func (s *rSCIONPacketSecurityExt) Offset() int {
	return s.start
}

func (s *rSCIONPacketSecurityExt) Len() int {
	return len(s.raw)
}

func (s *rSCIONPacketSecurityExt) Class() common.L4ProtocolType {
	return common.End2EndClass
}

func (s *rSCIONPacketSecurityExt) Type() common.ExtnType {
	return common.ExtnSCIONPacketSecurityType
}

func (s *rSCIONPacketSecurityExt) String() string {
	// Delegate string representation to spkt.Traceroute
	e, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SecurityExt - %v: %v", err.Desc, err.String())
	}
	return e.String()
}

// limits is a helper function to return limits of a slice
func limits(h, byteSize int) (int, int) {
	return h, h + byteSize
}

// limitsMetadata returns the limits of the Metadata in the raw buffer
func limitsMetadata(SecMode uint8) (int, int) {
	var l, h int

	switch SecMode {
	case pkt_sec_extn.AES_CMAC:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH, pkt_sec_extn.AES_CMAC_META_LENGTH)
	case pkt_sec_extn.HMAC_SHA256:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH, pkt_sec_extn.HMAC_SHA256_META_LENGTH)
	case pkt_sec_extn.ED25519:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH, pkt_sec_extn.ED25519_META_LENGTH)
	case pkt_sec_extn.GCM_AES128:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH, pkt_sec_extn.GCM_AES128_META_LENGTH)
	case pkt_sec_extn.SCMP_AUTH_DRKEY:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH, scmp_auth_extn.DRKEY_META_LENGTH)
	case pkt_sec_extn.SCMP_AUTH_HASH_TREE:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH, scmp_auth_extn.HASH_TREE_META_LENGTH)
	default:
		return -1, -1 // Shall not land here. Will cause panic
	}

	return l, h
}

// limitsAuthenticator returns the limits of the Authenticator in the raw buffer
func limitsAuthenticator(SecMode uint8, maxLen int) (int, int) {
	var l, h int

	switch SecMode {
	case pkt_sec_extn.AES_CMAC:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH+pkt_sec_extn.AES_CMAC_META_LENGTH, pkt_sec_extn.AES_CMAC_AUTH_LENGTH)
	case pkt_sec_extn.HMAC_SHA256:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH+pkt_sec_extn.HMAC_SHA256_META_LENGTH, pkt_sec_extn.HMAC_SHA256_AUTH_LENGTH)
	case pkt_sec_extn.ED25519:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH+pkt_sec_extn.ED25519_META_LENGTH, pkt_sec_extn.ED25519_AUTH_LENGTH)
	case pkt_sec_extn.GCM_AES128:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH+pkt_sec_extn.GCM_AES128_META_LENGTH, pkt_sec_extn.GCM_AES128_AUTH_LENGTH)
	case pkt_sec_extn.SCMP_AUTH_DRKEY:
		l, h = limits(pkt_sec_extn.SECMODE_LENGTH+scmp_auth_extn.DRKEY_META_LENGTH, scmp_auth_extn.DRKEY_AUTH_LENGTH)
	case pkt_sec_extn.SCMP_AUTH_HASH_TREE:
		l = pkt_sec_extn.SECMODE_LENGTH + scmp_auth_extn.HASH_TREE_META_LENGTH
		h = maxLen // Shall not land here. Will cause panic
	default:
		return -1, -1
	}
	return l, h
}
