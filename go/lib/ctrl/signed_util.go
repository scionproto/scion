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
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

// Signer takes a Pld and signs it, producing a SignedPld.
type Signer interface {
	Sign(*Pld) (*SignedPld, error)
}

// SigVerifier verifies the signature of a SignedPld.
type SigVerifier interface { // interfaces -> infra
	Verify(context.Context, *SignedPld) error
}

// VerifySig does some sanity checks on p, and then verifies the signature using sigV.
func VerifySig(ctx context.Context, p *SignedPld, sigV SigVerifier) error {
	// Perform common checks before calling real checker.
	if p.Sign.Type == proto.SignType_none && len(p.Sign.Signature) == 0 {
		// Nothing to check.
		return nil
	}
	if p.Sign.Type == proto.SignType_none {
		return common.NewBasicError("SignedPld has signature of type none", nil)
	}
	if len(p.Sign.Signature) == 0 {
		return common.NewBasicError("SignedPld is missing signature", nil, "type", p.Sign.Type)
	}
	return sigV.Verify(ctx, p)
}

const (
	// SrcDefaultPrefix is the default prefix for proto.SignS.Src.
	SrcDefaultPrefix = "DEFAULT: "
	// SrcDefaultFmt is the default format for proto.SignS.Src.
	SrcDefaultFmt = `^` + SrcDefaultPrefix + `IA: (\S+) CHAIN: (\d+) TRC: (\d+)$`
)

type SignSrcDef struct {
	IA       addr.IA
	ChainVer uint64
	TRCVer   uint64
}

func NewSignSrcDefFromRaw(b common.RawBytes) (*SignSrcDef, error) {
	re := regexp.MustCompile(SrcDefaultFmt)
	s := re.FindStringSubmatch(string(b))
	if len(s) == 0 {
		return nil, common.NewBasicError("Unable to match default src", nil, "string", string(b))
	}
	ia, err := addr.IAFromString(s[1])
	if err != nil {
		return nil, common.NewBasicError("Unable to parse default src IA", err)
	}
	chainVer, err := strconv.ParseUint(s[2], 10, 64)
	if err != nil {
		return nil, common.NewBasicError("Unable to parse default src ChainVer", err)
	}
	trcVer, err := strconv.ParseUint(s[3], 10, 64)
	if err != nil {
		return nil, common.NewBasicError("Unable to parse default src TRCVer", err)
	}
	return &SignSrcDef{IA: ia, ChainVer: chainVer, TRCVer: trcVer}, nil
}

func (s *SignSrcDef) Pack() common.RawBytes {
	return common.RawBytes(fmt.Sprintf("%sIA: %s CHAIN: %d TRC: %d", SrcDefaultPrefix,
		s.IA, s.ChainVer, s.TRCVer))
}

func (s *SignSrcDef) String() string {
	return fmt.Sprintf("IA: %s ChainVer: %d TRCVer: %d", s.IA, s.ChainVer, s.TRCVer)
}
