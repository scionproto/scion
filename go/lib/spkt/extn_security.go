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

//
//    0B       1        2        3        4        5        6        7
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | xxxxxxxxxxxxxxxxxxxxxxxx |SecMode |       Metadata (var length)       |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                      Authenticator (var length)                       |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//
//    len(Metadata)      = 4 + 8i , where i in [0,1,...]
//    len(Authenticator) = 8i     , where i in [1,2,...]

package spkt

import (
	"bytes"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
)

var _ common.Extension = (*SecurityExtn)(nil)

const (
	// Basic definitions
	SECMODE_LENGTH   = 1
	TIMESTAMP_LENGTH = 4

	// SecMode codes
	AES_CMAC               uint8 = 0
	HMAC_SHA256            uint8 = 1
	ED25519                uint8 = 2
	GCM_AES128             uint8 = 3
	SCMP_AUTH_DRKEY        uint8 = 4
	SCMP_AUTH_HASHED_DRKEY uint8 = 5
	SCMP_AUTH_HASH_TREE    uint8 = 6

	// Metadata length (Shall be 4 + i*8, were i in [0,1,...])
	AES_CMAC_META_LENGTH    = TIMESTAMP_LENGTH
	HMAC_SHA256_META_LENGTH = TIMESTAMP_LENGTH
	ED25519_META_LENGTH     = TIMESTAMP_LENGTH
	GCM_AES128_META_LENGTH  = TIMESTAMP_LENGTH

	// Authenticator length
	AES_CMAC_AUTH_LENGTH    = 16
	HMAC_SHA256_AUTH_LENGTH = 32
	ED25519_AUTH_LENGTH     = 64
	GCM_AES128_AUTH_LENGTH  = 16

	AES_CMAC_TOTAL_LENGTH    = SECMODE_LENGTH + AES_CMAC_META_LENGTH + AES_CMAC_AUTH_LENGTH
	HMAC_SHA256_TOTAL_LENGTH = SECMODE_LENGTH + HMAC_SHA256_META_LENGTH + HMAC_SHA256_AUTH_LENGTH
	ED25519_TOTAL_LENGTH     = SECMODE_LENGTH + ED25519_META_LENGTH + ED25519_AUTH_LENGTH
	GCM_AES128_TOTAL_LENGTH  = SECMODE_LENGTH + GCM_AES128_META_LENGTH + GCM_AES128_AUTH_LENGTH
)

type SecurityExtn struct {
	SecMode       uint8
	Metadata      common.RawBytes
	Authenticator common.RawBytes
}

func NewSecurityExtn(SecMode uint8) *SecurityExtn {
	s := &SecurityExtn{SecMode: SecMode}

	var metaLen, authLen int

	switch SecMode {
	case AES_CMAC:
		metaLen = AES_CMAC_META_LENGTH
		authLen = AES_CMAC_AUTH_LENGTH
	case HMAC_SHA256:
		metaLen = HMAC_SHA256_META_LENGTH
		authLen = HMAC_SHA256_META_LENGTH
	case ED25519:
		metaLen = ED25519_META_LENGTH
		authLen = ED25519_AUTH_LENGTH
	case GCM_AES128:
		metaLen = GCM_AES128_META_LENGTH
		authLen = GCM_AES128_AUTH_LENGTH
	default:
		panic("Invalid SecMode!")
		// TODO(roosd) Handle case, but should not be possible!
	}

	s.Metadata = make(common.RawBytes, metaLen)
	s.Authenticator = make(common.RawBytes, authLen)

	return s
}

// Update the Metadata.
func (s *SecurityExtn) UpdateMetadata(metadata common.RawBytes) *common.Error {
	if len(s.Metadata) != len(metadata) {
		return common.NewError("The length does not match",
			"required len", len(s.Metadata), "provided len", len(metadata))
	}
	copy(s.Metadata, metadata)
	return nil
}

// Update the Authenticator.
func (s *SecurityExtn) UpdateAuthenticator(authenticator common.RawBytes) *common.Error {
	if len(s.Authenticator) != len(authenticator) {
		return common.NewError("The length does not match",
			"required len", len(s.Authenticator), "provided len", len(authenticator))
	}
	copy(s.Authenticator, authenticator)
	return nil
}

func (s *SecurityExtn) Write(b common.RawBytes) *common.Error {
	if len(b) < s.Len() {
		return common.NewError("Buffer too short", "method", "SecurityExtn.Write")
	}
	b[0] = uint8(s.SecMode)

	l := SECMODE_LENGTH + len(s.Metadata)
	h := l + len(s.Authenticator)

	copy(b[SECMODE_LENGTH:l], s.Metadata)
	copy(b[l:h], s.Authenticator)
	return nil
}

func (s *SecurityExtn) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, s.Len())
	if err := s.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *SecurityExtn) Copy() common.Extension {
	c := NewSecurityExtn(s.SecMode)
	copy(c.Metadata, s.Metadata)
	copy(c.Authenticator, s.Authenticator)
	return c
}

func (s *SecurityExtn) Reverse() (bool, *common.Error) {
	// Nothing to do.
	return true, nil
}

func (s *SecurityExtn) Len() int {
	return SECMODE_LENGTH + len(s.Metadata) + len(s.Authenticator)
}

func (s *SecurityExtn) Class() common.L4ProtocolType {
	return common.End2EndClass
}

func (s *SecurityExtn) Type() common.ExtnType {
	return common.ExtnSecurityType
}

func (s *SecurityExtn) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "SecurityExtn (%dB): SecMode: %d\n", s.Len(), s.SecMode)
	fmt.Fprintf(buf, " Metadata: %s", s.Metadata.String())
	fmt.Fprintf(buf, " Authenticator: %s", s.Authenticator.String())
	return buf.String()
}
