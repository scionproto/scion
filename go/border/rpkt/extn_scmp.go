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

// This file contains the router's implementation of the SCMP hop-by-hop
// extension.

package rpkt

import (
	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
)

var _ rExtension = (*rSCMPExt)(nil)

// rSCMPExt is the router's representation of the SCMP extension.
type rSCMPExt struct {
	*scmp.Extn
	rp  *RtrPkt
	raw common.RawBytes
	log.Logger
}

func rSCMPExtFromRaw(rp *RtrPkt, start, end int) (*rSCMPExt, error) {
	var err error
	s := &rSCMPExt{rp: rp, raw: rp.Raw[start:end]}
	s.Extn, err = scmp.ExtnFromRaw(s.raw)
	if err != nil {
		return nil, err
	}
	s.Logger = rp.Logger.New("ext", "scmp")
	if s.Extn.Error {
		// SCMP Errors must never generate an error response.
		rp.SCMPError = true
	}
	return s, nil
}

func (s *rSCMPExt) RegisterHooks(h *hooks) error {
	if s.HopByHop {
		// If the extension's hop-by-hop flag is set, then process the payload.
		h.Payload = append(h.Payload, s.rp.parseSCMPPayload)
		h.Process = append(h.Process, s.rp.processSCMP)
	}
	return nil
}

func (s *rSCMPExt) GetExtn() (common.Extension, error) {
	return s.Extn, nil
}
