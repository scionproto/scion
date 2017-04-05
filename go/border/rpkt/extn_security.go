// Copyright 2016 ETH Zurich
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

// This file contains the router's representation of the end-2-end Security
// extension.

package rpkt

import (
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spkt"
)

var _ rExtension = (*rSecurityExt)(nil)

// rSCMPAuthExt is the router's representation of the SCMPAuth extension.
type rSecurityExt struct {
	rp      *RtrPkt
	raw     common.RawBytes
	start   int
	SecMode uint8
	log.Logger
}

// rSecurityExtFromRaw creates an rSecurityExt instance from raw bytes, keeping a
// reference to the location in the packet's buffer.
func rSecurityExtFromRaw(rp *RtrPkt, start, end int) (*rSecurityExt, *common.Error) {
	s := &rSecurityExt{rp: rp, raw: rp.Raw[start:end]}
	s.start = start
	s.SecMode = s.raw[0]
	s.Logger = rp.Logger.New("ext", "security")
	return s, nil
}

// Metadata returns a slice of the underlying buffer
func (s *rSecurityExt) Metadata() common.RawBytes {
	l, h := limitsMetadata(s.SecMode)
	return s.raw[l:h]
}

// Update the Metadata directly in the underlying buffer.
func (s *rSecurityExt) UpdateMetadata(metadata common.RawBytes) {
	slice := s.Metadata()
	copy(slice, metadata)
}

// Authenticator returns a slice of the underlying buffer
func (s *rSecurityExt) Authenticator() common.RawBytes {
	l, h := limitsAuthenticator(s.SecMode, len(s.raw))
	return s.raw[l:h]
}

// Update the Authenticator directly in the underlying buffer.
func (s *rSecurityExt) UpdateAuthenticator(authenticator common.RawBytes) *common.Error {
	slice := s.Authenticator()
	copy(slice, authenticator)
	return nil
}

func (s *rSecurityExt) RegisterHooks(h *hooks) *common.Error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSecurityExt) Validate() (HookResult, *common.Error) {
	// Check valid SecMode code
	if s.SecMode > spkt.SCMP_AUTH_HASH_TREE {
		return HookError, common.NewError("SecMode not supported", "code", s.SecMode)
	}

	// Check valid lengths. Can be optimized by ori-ing instead of switching
	notMatchingLen := false
	switch {
	case spkt.AES_CMAC == s.SecMode && (len(s.raw) != spkt.AES_CMAC_TOTAL_LENGTH):
		notMatchingLen = true
	case spkt.HMAC_SHA256 == s.SecMode && (len(s.raw) != spkt.HMAC_SHA256_TOTAL_LENGTH):
		notMatchingLen = true
	case spkt.ED25519 == s.SecMode && (len(s.raw) != spkt.ED25519_TOTAL_LENGTH):
		notMatchingLen = true
	case spkt.GCM_AES128 == s.SecMode && (len(s.raw) != spkt.GCM_AES128_TOTAL_LENGTH):
		notMatchingLen = true
	case spkt.SCMP_AUTH_DRKEY == s.SecMode && (len(s.raw) != spkt.SCMP_AUTH_DRKEY_TOTAL_LENGTH):
		notMatchingLen = true
	case spkt.SCMP_AUTH_HASHED_DRKEY == s.SecMode && (len(s.raw) != spkt.SCMP_AUTH_HASHED_DRKEY_TOTAL_LENGTH):
		notMatchingLen = true
	case spkt.SCMP_AUTH_HASH_TREE == s.SecMode && (len(s.raw) != hashTreeTotalLength(hashTreeHeight(s.raw))):
		notMatchingLen = true
	}

	if notMatchingLen {
		return HookError, common.NewError("Header length does not match the definition", "len", len(s.raw))
	}

	return HookContinue, nil
}

// GetExtn returns the spkt.Security representation,
// which does not have direct access to the underling buffer.
func (r *rSecurityExt) GetExtn() (common.Extension, *common.Error) {
	// TODO(roosd) handle faulty secmode codes
	var s common.Extension

	if r.SecMode == spkt.SCMP_AUTH_DRKEY || r.SecMode == spkt.SCMP_AUTH_HASHED_DRKEY {
		s = spkt.NewSCMPDRKeyAuthExtn(r.SecMode)
		s.(*spkt.SCMPAuthExtn).UpdateMetadata(r.Metadata())
		s.(*spkt.SCMPAuthExtn).UpdateAuthenticator(r.Authenticator())
	} else if r.SecMode == spkt.SCMP_AUTH_HASH_TREE {
		s = spkt.NewSCMPHashedTreeExtn(r.SecMode, hashTreeHeight(r.raw))
		s.(*spkt.SCMPAuthExtn).UpdateMetadata(r.Metadata())
		s.(*spkt.SCMPAuthExtn).UpdateAuthenticator(r.Authenticator())
	} else {
		s = spkt.NewSecurityExtn(r.SecMode)
		s.(*spkt.SecurityExtn).UpdateMetadata(r.Metadata())
		s.(*spkt.SecurityExtn).UpdateAuthenticator(r.Authenticator())
	}
	return s, nil
}

func (s *rSecurityExt) Offset() int {
	return s.start
}

func (s *rSecurityExt) Len() int {
	return len(s.raw)
}

func (s *rSecurityExt) Class() common.L4ProtocolType {
	return common.End2EndClass
}

func (s *rSecurityExt) Type() common.ExtnType {
	return common.ExtnSecurityType
}

func (s *rSecurityExt) String() string {
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
	case spkt.AES_CMAC:
		l, h = limits(spkt.SECMODE_LENGTH, spkt.AES_CMAC_META_LENGTH)
	case spkt.HMAC_SHA256:
		l, h = limits(spkt.SECMODE_LENGTH, spkt.HMAC_SHA256_META_LENGTH)
	case spkt.ED25519:
		l, h = limits(spkt.SECMODE_LENGTH, spkt.ED25519_META_LENGTH)
	case spkt.GCM_AES128:
		l, h = limits(spkt.SECMODE_LENGTH, spkt.GCM_AES128_META_LENGTH)
	case spkt.SCMP_AUTH_DRKEY:
		l, h = limits(spkt.SECMODE_LENGTH, spkt.SCMP_AUTH_DRKEY_META_LENGTH)
	case spkt.SCMP_AUTH_HASHED_DRKEY:
		l, h = limits(spkt.SECMODE_LENGTH, spkt.SCMP_AUTH_HASHED_DRKEY_META_LENGTH)
	case spkt.SCMP_AUTH_HASH_TREE:
		l, h = limits(spkt.SECMODE_LENGTH, spkt.SCMP_AUTH_HASH_TREE_META_LENGTH)
	default:
		return -1, -1 // Shall not land here. Will cause panic
	}

	return l, h
}

// limitsAuthenticator returns the limits of the Authenticator in the raw buffer
func limitsAuthenticator(SecMode uint8, maxLen int) (int, int) {
	var l, h int

	switch SecMode {
	case spkt.AES_CMAC:
		l, h = limits(spkt.SECMODE_LENGTH+spkt.AES_CMAC_META_LENGTH, spkt.AES_CMAC_AUTH_LENGTH)
	case spkt.HMAC_SHA256:
		l, h = limits(spkt.SECMODE_LENGTH+spkt.HMAC_SHA256_META_LENGTH, spkt.HMAC_SHA256_AUTH_LENGTH)
	case spkt.ED25519:
		l, h = limits(spkt.SECMODE_LENGTH+spkt.ED25519_META_LENGTH, spkt.ED25519_AUTH_LENGTH)
	case spkt.GCM_AES128:
		l, h = limits(spkt.SECMODE_LENGTH+spkt.GCM_AES128_META_LENGTH, spkt.GCM_AES128_AUTH_LENGTH)
	case spkt.SCMP_AUTH_DRKEY:
		l, h = limits(spkt.SECMODE_LENGTH+spkt.SCMP_AUTH_DRKEY_META_LENGTH, spkt.SCMP_AUTH_DRKEY_AUTH_LENGTH)
	case spkt.SCMP_AUTH_HASHED_DRKEY:
		l, h = limits(spkt.SECMODE_LENGTH+spkt.SCMP_AUTH_HASHED_DRKEY_META_LENGTH, spkt.SCMP_AUTH_HASHED_DRKEY_AUTH_LENGTH)
	case spkt.SCMP_AUTH_HASH_TREE:
		l = spkt.SECMODE_LENGTH + spkt.SCMP_AUTH_HASH_TREE_META_LENGTH
		h = maxLen // Shall not land here. Will cause panic
	default:
		return -1, -1
	}
	return l, h
}
