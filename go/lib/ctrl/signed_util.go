// Copyright 2018 ETH Zurich
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

package ctrl

import (
	"context"
	"fmt"
	"regexp"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/proto"
)

// Signer takes a message and signs it, producing the signature metadata.
type Signer interface {
	Sign(msg []byte) (*proto.SignS, error)
}

// Verifier verifies the signature of a signed payload.
type Verifier interface {
	VerifyPld(context.Context, *SignedPld) (*Pld, error)
}

const (
	// SrcDefaultPrefix is the default prefix for proto.SignS.Src.
	SrcDefaultPrefix = "DEFAULT: "
	// SrcDefaultFmt is the default format for proto.SignS.Src.
	SrcDefaultFmt = `^` + SrcDefaultPrefix + `IA: (\S+) CHAIN: (\d+) TRC: (\d+)$`
)

var reSrcDefault = regexp.MustCompile(SrcDefaultFmt)

// SignSrcDef is the default format for signature source. It states the
// signing entity, and the certificate chain authenticating the public key.
// The TRC version is a hint for the TRC that can currently be used to
// verify the chain.
type SignSrcDef struct {
	IA       addr.IA
	ChainVer scrypto.Version
	TRCVer   scrypto.Version
}

func NewSignSrcDefFromRaw(b common.RawBytes) (SignSrcDef, error) {
	match := reSrcDefault.FindSubmatch(b)
	if len(match) == 0 {
		return SignSrcDef{}, common.NewBasicError("Unable to match default src", nil,
			"string", string(b))
	}
	ia, err := addr.IAFromString(string(match[1]))
	if err != nil {
		return SignSrcDef{}, common.NewBasicError("Unable to parse default src IA", err)
	}
	var chainVer, trcVer scrypto.Version
	if err := chainVer.UnmarshalJSON(match[2]); err != nil {
		return SignSrcDef{}, common.NewBasicError("Unable to parse default src ChainVer", err)
	}
	if err := trcVer.UnmarshalJSON(match[3]); err != nil {
		return SignSrcDef{}, common.NewBasicError("Unable to parse default src TRCVer", err)
	}
	return SignSrcDef{IA: ia, ChainVer: chainVer, TRCVer: trcVer}, nil
}

// IsUninitialized indicates whether the source is equal to the zero value.
func (s *SignSrcDef) IsUninitialized() bool {
	return *s == SignSrcDef{}
}

func (s *SignSrcDef) Pack() common.RawBytes {
	return common.RawBytes(fmt.Sprintf("%sIA: %s CHAIN: %d TRC: %d", SrcDefaultPrefix,
		s.IA, s.ChainVer, s.TRCVer))
}

func (s *SignSrcDef) String() string {
	return fmt.Sprintf("IA: %s ChainVer: %d TRCVer: %d", s.IA, s.ChainVer, s.TRCVer)
}

func (s *SignSrcDef) Equal(t SignSrcDef) bool {
	switch {
	case !s.IA.Equal(t.IA):
		return false
	case s.ChainVer != t.ChainVer:
		return false
	case s.TRCVer != t.TRCVer:
		return false
	}
	return true
}
