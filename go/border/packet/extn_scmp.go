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

package packet

import (
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

var _ Extension = (*SCMPExt)(nil)

type SCMPExt struct {
	data     []byte
	Error    bool
	HopByHop bool
	log.Logger
}

func SCMPExtFromRaw(b []byte, logger log.Logger) (*SCMPExt, *util.Error) {
	s := &SCMPExt{}
	s.data = b
	flags := b[3] // Index past ext subheader
	s.Error = (flags & 0x01) != 0
	s.HopByHop = (flags & 0x02) != 0
	s.Logger = logger
	s.Debug("SCMP extension found", "error", s.Error, "hopbyhop", s.HopByHop)
	return s, nil
}

func (s *SCMPExt) RegisterHooks(h *Hooks) *util.Error {
	if s.HopByHop {
		h.Process = append(h.Process, s.Process)
	}
	return nil
}

func (s *SCMPExt) String() string {
	return fmt.Sprintf("SCMP Ext(%dB): Error? %v HopByHop: %v", spkt.LineLen, s.Error, s.HopByHop)
}

func (s *SCMPExt) Process() (HookResult, *util.Error) {

	return HookFinish, nil
}
