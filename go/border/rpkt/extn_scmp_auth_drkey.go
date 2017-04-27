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

// This file contains the router's representation of the end-2-end SCMPAuth
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
	if mode != pkt_sec_extn.SCMP_AUTH_DRKEY {
		return nil, common.NewError("SecMode not supported", "mode", mode)
	}
	s := &rSCMPAuthDRKeyExt{
		&rSCIONPacketSecurityBaseExt{rp: rp, raw: raw, start: start, SecMode: mode}}
	s.Logger = rp.Logger.New("ext", "SCMPAuthDRKeyExt")
	return s, nil
}

func (s *rSCMPAuthDRKeyExt) String() string {
	// Delegate string representation to spkt.SCMPAuthDRKeyExtn
	e, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCMPAuthDRKey - %v: %v", err.Desc, err.String())
	}
	return e.String()
}

func (s *rSCMPAuthDRKeyExt) RegisterHooks(h *hooks) *common.Error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSCMPAuthDRKeyExt) Validate() (HookResult, *common.Error) {
	if s.SecMode != pkt_sec_extn.SCMP_AUTH_DRKEY {
		return HookError, common.NewError("SecMode not supported", "mode", s.SecMode)
	}
	if len(s.raw) != scmp_auth_extn.DRKEY_TOTAL_LENGTH {
		return HookError, common.NewError("Invalid header length", "len", len(s.raw))
	}
	return HookContinue, nil
}

// GetExtn returns the spkt.Security representation,
// which does not have direct access to the underling buffer.
func (s *rSCMPAuthDRKeyExt) GetExtn() (common.Extension, *common.Error) {
	c := scmp_auth_extn.NewSCMPAuthDRKeyExtn()
	if e := c.UpdateDirection(s.Direction()); e != nil {
		return nil, e
	}
	c.UpdateMAC(s.MAC())
	return c, nil
}

func (s *rSCMPAuthDRKeyExt) UpdateDirection(dir uint8) {
	s.raw[scmp_auth_extn.DIRECTION_OFFSET] = dir
}

func (s *rSCMPAuthDRKeyExt) Direction() uint8 {
	return s.raw[scmp_auth_extn.DIRECTION_OFFSET]
}

func (s *rSCMPAuthDRKeyExt) ResetMac() {
	for i := range s.MAC() {
		s.MAC()[i] = 0
	}
}

func (s *rSCMPAuthDRKeyExt) UpdateMAC(mac common.RawBytes) *common.Error {
	if len(s.MAC()) != len(mac) {
		return common.NewError("Invalid MAC length", "len", len(mac))
	}
	copy(s.MAC(), mac)
	return nil
}

func (s *rSCMPAuthDRKeyExt) MAC() common.RawBytes {
	return s.raw[scmp_auth_extn.MAC_OFFSET:scmp_auth_extn.DRKEY_TOTAL_LENGTH]
}
