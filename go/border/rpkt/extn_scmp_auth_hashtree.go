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
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn/scmp_auth_extn"
)

var _ rExtension = (*rSCMPAuthHashTreeExt)(nil)

type rSCMPAuthHashTreeExt struct {
	*rSCIONPacketSecurityBaseExt
}

// rSCMPAuthHashTreeExtFromRaw creates an rSCMPAuthHashTreeExt instance from raw bytes,
// keeping a reference to the location in the packet's buffer.
func rSCMPAuthHashTreeExtFromRaw(rp *RtrPkt, start, end int) (*rSCMPAuthHashTreeExt, *common.Error) {
	raw := rp.Raw[start:end]
	mode := raw[0]
	if mode != spse.ScmpAuthHashTree {
		return nil, common.NewError("SecMode not supported", "mode", mode,
			"expected", spse.ScmpAuthHashTree)
	}
	s := &rSCMPAuthHashTreeExt{
		&rSCIONPacketSecurityBaseExt{rp: rp, raw: raw, start: start, SecMode: mode}}
	s.Logger = rp.Logger.New("ext", "SCMPAuthHashTreeExt")
	return s, nil
}

func (s *rSCMPAuthHashTreeExt) String() string {
	// Delegate string representation to scmp.AuthHashTreeExtn
	extn, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCMPAuthHashTree - %v: %v", err.Desc, err.String())
	}
	return extn.String()
}

func (s *rSCMPAuthHashTreeExt) RegisterHooks(h *hooks) *common.Error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSCMPAuthHashTreeExt) Validate() (HookResult, *common.Error) {
	if s.SecMode != spse.ScmpAuthHashTree {
		return HookError, common.NewError("SecMode not supported", "mode", s.SecMode,
			"expected", spse.ScmpAuthHashTree)
	}
	if len(s.raw) != s.TotalLength() {
		return HookError, common.NewError("Invalid header length", "len", len(s.raw),
			"expected", s.TotalLength())
	}
	return HookContinue, nil
}

// GetExtn returns the spkt.Security representation,
// which does not have direct access to the underling buffer.
func (s *rSCMPAuthHashTreeExt) GetExtn() (common.Extension, *common.Error) {
	extn := scmp.NewAuthHashTreeExtn(s.Height())
	extn.SetOrder(s.Order())
	extn.SetSignature(s.Signature())
	extn.SetHashes(s.Hashes())
	return extn, nil
}

func (s *rSCMPAuthHashTreeExt) SetHeight(height uint8) {
	s.raw[scmp.HeightOffset] = height
}

func (s *rSCMPAuthHashTreeExt) Height() uint8 {
	return s.raw[scmp.HeightOffset]
}

func (s *rSCMPAuthHashTreeExt) TotalLength() int {
	return totalLength(s.Height())
}

func (s *rSCMPAuthHashTreeExt) SetOrder(order common.RawBytes) *common.Error {
	if len(order) != scmp.OrderLength {
		return common.NewError("Invalid order length.", "len", len(order),
			"expected", scmp.OrderLength)
	}
	copy(s.raw[scmp.OrderOffset:scmp.SignatureOffset], order)
	return nil

}

func (s *rSCMPAuthHashTreeExt) Order() common.RawBytes {
	return s.raw[scmp.OrderOffset:scmp.SignatureOffset]
}

func (s *rSCMPAuthHashTreeExt) SetSignature(signature common.RawBytes) *common.Error {
	if len(signature) != scmp.SignatureLength {
		return common.NewError("Invalid signature length.", "len", len(signature),
			"expected", scmp.SignatureLength)
	}
	copy(s.raw[scmp.SignatureOffset:scmp.HashesOffset], signature)
	return nil
}

func (s *rSCMPAuthHashTreeExt) Signature() common.RawBytes {
	return s.raw[scmp.SignatureOffset:scmp.HashesOffset]
}

func (s *rSCMPAuthHashTreeExt) SetHashes(hashes common.RawBytes) *common.Error {
	if len(hashes) != hashesLength(s.Height()) {
		return common.NewError("Invalid hashes length", "len", len(hashes),
			"expected", hashesLength(s.Height()))
	}
	copy(s.raw[scmp.HashesOffset:s.TotalLength()], hashes)
	return nil

}

func (s *rSCMPAuthHashTreeExt) Hashes() common.RawBytes {
	return s.raw[scmp.HashesOffset:s.TotalLength()]
}

func hashesLength(height uint8) int {
	return int(height) * scmp.HashLength
}

func totalLength(height uint8) int {
	return scmp.HashesOffset + hashesLength(height)
}
