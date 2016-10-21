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
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

var _ Extension = (*SCMPExt)(nil)

type SCMPExt struct {
	p        *RPkt
	raw      util.RawBytes
	Error    bool
	HopByHop bool
	log.Logger
}

func SCMPExtFromRaw(p *RPkt, start, end int) (*SCMPExt, *util.Error) {
	s := &SCMPExt{p: p, raw: p.Raw[start:end]}
	flags := s.raw[3] // Index past ext subheader
	s.Error = (flags & 0x01) != 0
	s.HopByHop = (flags & 0x02) != 0
	s.Logger = p.Logger.New("ext", "scmp")
	s.Debug("SCMP extension found", "error", s.Error, "hopbyhop", s.HopByHop)
	if s.Error {
		// SCMP Errors should never generate an error response.
		p.SCMPError = true
	}
	return s, nil
}

func (s *SCMPExt) RegisterHooks(h *Hooks) *util.Error {
	if s.HopByHop {
		h.Payload = append(h.Payload, s.p.parseSCMPPayload)
		h.Process = append(h.Process, s.p.processSCMP)
	}
	return nil
}

func (s *SCMPExt) String() string {
	return fmt.Sprintf("SCMP Ext(%dB): Error? %v HopByHop: %v", common.LineLen, s.Error, s.HopByHop)
}
