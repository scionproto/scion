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

// This file contains the router's representation of the end-to-end SCMPAuthDRKey
// extension.

package rpkt

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn/scmp_auth_extn"
)

var _ rExtension = (*rSCMPAuthDRKeyExt)(nil)

type rSCMPAuthDRKeyExt struct {
	*rSCIONPacketSecurityBaseExt
}

// rSCMPAuthDRKeyExtFromRaw creates an rSCMPAuthDRKeyExt instance from raw bytes,
// keeping a reference to the location in the packet's buffer.
func rSCMPAuthDRKeyExtFromRaw(rp *RtrPkt, start, end int) (*rSCMPAuthDRKeyExt, *common.Error) {
	raw := rp.Raw[start:end]
	mode := raw[0]
	if mode != spse.ScmpAuthDRKey {
		return nil, common.NewError("SecMode not supported", "mode", mode)
	}
	s := &rSCMPAuthDRKeyExt{
		&rSCIONPacketSecurityBaseExt{rp: rp, raw: raw, start: start, SecMode: mode}}
	s.Logger = rp.Logger.New("ext", "SCMPAuthDRKeyExt")
	return s, nil
}

func (s *rSCMPAuthDRKeyExt) String() string {
	// Delegate string representation to scmp.AuthDRKeyExtn
	extn, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCMPAuthDRKey - %v: %v", err.Desc, err.String())
	}
	return extn.String()
}

func (s *rSCMPAuthDRKeyExt) RegisterHooks(h *hooks) *common.Error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSCMPAuthDRKeyExt) Validate() (HookResult, *common.Error) {
	if s.SecMode != spse.ScmpAuthDRKey {
		return HookError, common.NewError("SecMode not supported", "mode", s.SecMode,
			"expected", spse.ScmpAuthDRKey)
	}
	if len(s.raw) != scmp.DRKeyTotalLength {
		return HookError, common.NewError("Invalid header length", "len", len(s.raw),
			"expected", scmp.DRKeyTotalLength)
	}
	return HookContinue, nil
}

// GetExtn returns the spkt.Security representation,
// which does not have direct access to the underling buffer.
func (s *rSCMPAuthDRKeyExt) GetExtn() (common.Extension, *common.Error) {
	extn := scmp.NewAuthDRKeyExtn()
	if err := extn.SetDirection(s.Direction()); err != nil {
		return nil, err
	}
	extn.SetMAC(s.MAC())
	return extn, nil
}

func (s *rSCMPAuthDRKeyExt) SetDirection(dir uint8) {
	s.raw[scmp.DirectionOffset] = dir
}

func (s *rSCMPAuthDRKeyExt) Direction() uint8 {
	return s.raw[scmp.DirectionOffset]
}

func (s *rSCMPAuthDRKeyExt) ResetMac() {
	for i := range s.MAC() {
		s.MAC()[i] = 0
	}
}

func (s *rSCMPAuthDRKeyExt) SetMAC(mac common.RawBytes) *common.Error {
	if len(s.MAC()) != scmp.MACLength {
		return common.NewError("Invalid MAC length", "len", len(mac),
			"expected", scmp.MACLength)
	}
	copy(s.MAC(), mac)
	return nil
}

func (s *rSCMPAuthDRKeyExt) MAC() common.RawBytes {
	return s.raw[scmp.MACOffset:scmp.DRKeyTotalLength]
}
