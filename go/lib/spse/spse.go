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

package spse

import (
	"bytes"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
)

var _ common.Extension = (*Extn)(nil)

// BaseExtn is the base for Extn, scmp_auth.DRKeyExt and scmp_auth.HashTreeExt
type BaseExtn struct {
	SecMode uint8
}

// Implementation of the SCIONPacketSecurity extension.
type Extn struct {
	*BaseExtn
	Metadata      common.RawBytes
	Authenticator common.RawBytes
}

const (
	// Basic definitions
	SecModeLength   = 1
	TimestampLength = 4

	// SecMode codes
	AesCMac          uint8 = 0
	HmacSha256       uint8 = 1
	ED25519          uint8 = 2
	GcmAes128        uint8 = 3
	ScmpAuthDRKey    uint8 = 4
	ScmpAuthHashTree uint8 = 5

	// Metadata length (Shall be 4 + i*8, were i in [0,1,...])
	AesCMacMetaLength    = TimestampLength
	HmacSha256MetaLength = TimestampLength
	ED25519MetaLength    = TimestampLength
	GcmAes128MetaLength  = TimestampLength

	// Authenticator length
	AesCMacAuthLength    = 16
	HmacSha256AuthLength = 32
	ED25519AuthLength    = 64
	GcmAes128AuthLength  = 16

	AesCMacTotalLength    = SecModeLength + AesCMacMetaLength + AesCMacAuthLength
	HmacSha256TotalLength = SecModeLength + HmacSha256MetaLength + HmacSha256AuthLength
	ED25519TotalLength    = SecModeLength + ED25519MetaLength + ED25519AuthLength
	GcmAes128TotalLength  = SecModeLength + GcmAes128MetaLength + GcmAes128AuthLength
)

func IsSupported(mode uint8) bool {
	switch mode {
	case AesCMac:
	case HmacSha256:
	case ED25519:
	case GcmAes128:
	default:
		return false
	}
	return true
}

func (s *BaseExtn) Reverse() (bool, *common.Error) {
	// Nothing to do.
	return true, nil
}

func (s *BaseExtn) Class() common.L4ProtocolType {
	return common.End2EndClass
}

func (s *BaseExtn) Type() common.ExtnType {
	return common.ExtnSCIONPacketSecurityType
}

func NewExtn(secMode uint8) (*Extn, *common.Error) {
	s := &Extn{
		BaseExtn: &BaseExtn{SecMode: secMode}}

	var metaLen, authLen int

	switch secMode {
	case AesCMac:
		metaLen = AesCMacMetaLength
		authLen = AesCMacAuthLength
	case HmacSha256:
		metaLen = HmacSha256MetaLength
		authLen = HmacSha256MetaLength
	case ED25519:
		metaLen = ED25519MetaLength
		authLen = ED25519AuthLength
	case GcmAes128:
		metaLen = GcmAes128MetaLength
		authLen = GcmAes128AuthLength
	default:
		return nil, common.NewError("Invalid SecMode code.", "SecMode", secMode)
	}

	s.Metadata = make(common.RawBytes, metaLen)
	s.Authenticator = make(common.RawBytes, authLen)

	return s, nil
}

// Set the Metadata.
func (s *Extn) SetMetadata(metadata common.RawBytes) *common.Error {
	if len(s.Metadata) != len(metadata) {
		return common.NewError("The length does not match",
			"required len", len(s.Metadata), "provided len", len(metadata))
	}
	copy(s.Metadata, metadata)
	return nil
}

// Set the Authenticator.
func (s *Extn) SetAuthenticator(authenticator common.RawBytes) *common.Error {
	if len(s.Authenticator) != len(authenticator) {
		return common.NewError("The length does not match",
			"required len", len(s.Authenticator), "provided len", len(authenticator))
	}
	copy(s.Authenticator, authenticator)
	return nil
}

func (s *Extn) Write(b common.RawBytes) *common.Error {
	if len(b) < s.Len() {
		return common.NewError("Buffer too short", "method", "SCIONPacketSecurityExtn.Write")
	}
	b[0] = s.SecMode

	authOffset := SecModeLength + len(s.Metadata)
	totalLength := authOffset + len(s.Authenticator)

	copy(b[SecModeLength:authOffset], s.Metadata)
	copy(b[authOffset:totalLength], s.Authenticator)
	return nil
}

func (s *Extn) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, s.Len())
	if err := s.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Extn) Copy() common.Extension {
	c, _ := NewExtn(s.SecMode)
	copy(c.Metadata, s.Metadata)
	copy(c.Authenticator, s.Authenticator)
	return c
}

func (s *Extn) Len() int {
	return SecModeLength + len(s.Metadata) + len(s.Authenticator)
}

func (s *Extn) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "spse.Extn (%dB): SecMode: %d\n", s.Len(), s.SecMode)
	fmt.Fprintf(buf, " Metadata: %s", s.Metadata.String())
	fmt.Fprintf(buf, " Authenticator: %s", s.Authenticator.String())
	return buf.String()
}
