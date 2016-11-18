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

package rpkt

import (
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
)

var _ RExtension = (*RSCMPExt)(nil)

type RSCMPExt struct {
	*scmp.Extn
	rp  *RtrPkt
	raw common.RawBytes
	log.Logger
}

func RSCMPExtFromRaw(rp *RtrPkt, start, end int) (*RSCMPExt, *common.Error) {
	var err *common.Error
	s := &RSCMPExt{rp: rp, raw: rp.Raw[start:end]}
	s.Extn, err = scmp.ExtnFromRaw(s.raw)
	if err != nil {
		return nil, err
	}
	s.Logger = rp.Logger.New("ext", "scmp")
	if s.Extn.Error {
		// SCMP Errors should never generate an error response.
		rp.SCMPError = true
	}
	return s, nil
}

func (s *RSCMPExt) RegisterHooks(h *Hooks) *common.Error {
	if s.HopByHop {
		h.Payload = append(h.Payload, s.rp.parseSCMPPayload)
		h.Process = append(h.Process, s.rp.processSCMP)
	}
	return nil
}

func (s *RSCMPExt) GetExtn() (common.Extension, *common.Error) {
	return s.Extn, nil
}
