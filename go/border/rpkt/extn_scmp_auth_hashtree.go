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

// This file contains the router's representation of the end-to-end SCMPAuthHashTree
// extension.

package rpkt

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spse"
	"github.com/netsec-ethz/scion/go/lib/spse/scmp_auth"
)

var _ rExtension = (*rSCMPAuthHashTreeExtn)(nil)

// rSCMPAuthHashTreeExtn is the router's representation of the SCMPAuthHashTree extension.
type rSCMPAuthHashTreeExtn struct {
	*rSPSBaseExtn
}

// rSCMPAuthHashTreeExtnFromRaw creates an rSCMPAuthHashTreeExtn instance from raw bytes,
// keeping a reference to the location in the packet's buffer.
func rSCMPAuthHashTreeExtnFromRaw(rp *RtrPkt, start, end int) (*rSCMPAuthHashTreeExtn, *common.Error) {
	raw := rp.Raw[start:end]
	mode := raw[0]
	if mode != spse.ScmpAuthHashTree {
		return nil, common.NewError("SecMode not supported", "mode", mode,
			"expected", spse.ScmpAuthHashTree)
	}
	s := &rSCMPAuthHashTreeExtn{
		&rSPSBaseExtn{rp: rp, raw: raw, start: start, SecMode: mode}}
	s.Logger = rp.Logger.New("ext", "SCMPAuthHashTreeExt")
	return s, nil
}

func (s *rSCMPAuthHashTreeExtn) String() string {
	// Delegate string representation to scmp.AuthHashTreeExtn
	extn, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCMPAuthHashTree - %v: %v", err.Desc, err.String())
	}
	return extn.String()
}

func (s *rSCMPAuthHashTreeExtn) RegisterHooks(h *hooks) *common.Error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSCMPAuthHashTreeExtn) Validate() (HookResult, *common.Error) {
	if s.SecMode != spse.ScmpAuthHashTree {
		return HookError, common.NewError("SecMode not supported", "mode", s.SecMode,
			"expected", spse.ScmpAuthHashTree)
	}
	if s.Height() > scmp_auth.MaxHeight {
		return HookError, common.NewError("Invalid height", "height", s.Height(),
			"max height", scmp_auth.MaxHeight)
	}
	if len(s.raw) != s.TotalLength() {
		return HookError, common.NewError("Invalid header length", "len", len(s.raw),
			"expected", s.TotalLength())
	}
	return HookContinue, nil
}

// GetExtn returns the scmp_auth.HashTreeExtn representation,
// which does not have direct access to the underling buffer.
func (s *rSCMPAuthHashTreeExtn) GetExtn() (common.Extension, *common.Error) {
	extn, err := scmp_auth.NewHashTreeExtn(s.Height())
	if err != nil {
		return nil, err
	}
	extn.SetOrder(s.Order())
	extn.SetSignature(s.Signature())
	extn.SetHashes(s.Hashes())
	return extn, nil
}

func (s *rSCMPAuthHashTreeExtn) SetHeight(height uint8) {
	s.raw[scmp_auth.HeightOffset] = height
}

func (s *rSCMPAuthHashTreeExtn) Height() uint8 {
	return s.raw[scmp_auth.HeightOffset]
}

func (s *rSCMPAuthHashTreeExtn) TotalLength() int {
	return totalLength(s.Height())
}

func (s *rSCMPAuthHashTreeExtn) SetOrder(order common.RawBytes) *common.Error {
	if len(order) != scmp_auth.OrderLength {
		return common.NewError("Invalid order length.", "len", len(order),
			"expected", scmp_auth.OrderLength)
	}
	copy(s.raw[scmp_auth.OrderOffset:scmp_auth.SignatureOffset], order)
	return nil

}

func (s *rSCMPAuthHashTreeExtn) Order() common.RawBytes {
	return s.raw[scmp_auth.OrderOffset:scmp_auth.SignatureOffset]
}

func (s *rSCMPAuthHashTreeExtn) SetSignature(signature common.RawBytes) *common.Error {
	if len(signature) != scmp_auth.SignatureLength {
		return common.NewError("Invalid signature length.", "len", len(signature),
			"expected", scmp_auth.SignatureLength)
	}
	copy(s.raw[scmp_auth.SignatureOffset:scmp_auth.HashesOffset], signature)
	return nil
}

func (s *rSCMPAuthHashTreeExtn) Signature() common.RawBytes {
	return s.raw[scmp_auth.SignatureOffset:scmp_auth.HashesOffset]
}

func (s *rSCMPAuthHashTreeExtn) SetHashes(hashes common.RawBytes) *common.Error {
	if len(hashes) != hashesLength(s.Height()) {
		return common.NewError("Invalid hashes length", "len", len(hashes),
			"expected", hashesLength(s.Height()))
	}
	copy(s.raw[scmp_auth.HashesOffset:s.TotalLength()], hashes)
	return nil

}

func (s *rSCMPAuthHashTreeExtn) Hashes() common.RawBytes {
	return s.raw[scmp_auth.HashesOffset:s.TotalLength()]
}

func hashesLength(height uint8) int {
	return int(height) * scmp_auth.HashLength
}

func totalLength(height uint8) int {
	return scmp_auth.HashesOffset + hashesLength(height)
}
