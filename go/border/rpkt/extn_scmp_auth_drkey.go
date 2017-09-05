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
	"github.com/netsec-ethz/scion/go/lib/spse"
	"github.com/netsec-ethz/scion/go/lib/spse/scmp_auth"
)

var _ rExtension = (*rSCMPAuthDRKeyExtn)(nil)

// rSCMPAuthDRKeyExtn is the router's representation of the SCMPAuthDRKey extension.
type rSCMPAuthDRKeyExtn struct {
	*rSPSBaseExtn
}

// rSCMPAuthDRKeyExtnFromRaw creates an rSCMPAuthDRKeyExtn instance from raw bytes,
// keeping a reference to the location in the packet's buffer.
func rSCMPAuthDRKeyExtnFromRaw(rp *RtrPkt, start, end int) (*rSCMPAuthDRKeyExtn, error) {
	raw := rp.Raw[start:end]
	mode := spse.SecMode(raw[0])
	s := &rSCMPAuthDRKeyExtn{&rSPSBaseExtn{rp: rp, raw: raw, SecMode: mode}}
	s.Logger = rp.Logger.New("ext", "SCMPAuthDRKeyExt")
	return s, nil
}

func (s *rSCMPAuthDRKeyExtn) String() string {
	// Delegate string representation to scmp_auth.AuthDRKeyExtn
	extn, err := s.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCMPAuthDRKey: %v", err)
	}
	return extn.String()
}

func (s *rSCMPAuthDRKeyExtn) RegisterHooks(h *hooks) error {
	h.Validate = append(h.Validate, s.Validate)
	return nil
}

func (s *rSCMPAuthDRKeyExtn) Validate() (HookResult, error) {
	if len(s.raw) != scmp_auth.DRKeyTotalLength {
		return HookError, common.NewCError("Invalid header length", "expected",
			scmp_auth.DRKeyTotalLength, "actual", len(s.raw))
	}
	return HookContinue, nil
}

// GetExtn returns the scmp_auth.DRKeyExtn representation,
// which does not have direct access to the underlying buffer.
func (s *rSCMPAuthDRKeyExtn) GetExtn() (common.Extension, error) {
	extn := scmp_auth.NewDRKeyExtn()
	if err := extn.SetDirection(s.Direction()); err != nil {
		return nil, err
	}
	extn.SetMAC(s.MAC())
	return extn, nil
}

func (s *rSCMPAuthDRKeyExtn) Direction() scmp_auth.Dir {
	return scmp_auth.Dir(s.raw[scmp_auth.DirectionOffset])
}

func (s *rSCMPAuthDRKeyExtn) SetDirection(dir scmp_auth.Dir) {
	s.raw[scmp_auth.DirectionOffset] = uint8(dir)
}

func (s *rSCMPAuthDRKeyExtn) MAC() common.RawBytes {
	return s.raw[scmp_auth.MACOffset:scmp_auth.DRKeyTotalLength]
}

func (s *rSCMPAuthDRKeyExtn) SetMAC(mac common.RawBytes) error {
	if len(mac) != scmp_auth.MACLength {
		return common.NewCError("Invalid MAC length", "expected", len(s.MAC()),
			"actual", len(mac))
	}
	copy(s.MAC(), mac)
	return nil
}

func (s *rSCMPAuthDRKeyExtn) ResetMac() {
	for i := range s.MAC() {
		s.MAC()[i] = 0
	}
}
