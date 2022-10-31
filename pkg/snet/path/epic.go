// Copyright 2021 ETH Zurich
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

package path

import (
	"sync"
	"time"

	libepic "github.com/scionproto/scion/pkg/experimental/epic"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
)

type EPIC struct {
	AuthPHVF []byte
	AuthLHVF []byte
	SCION    []byte

	mu      sync.Mutex
	counter uint32
}

func NewEPICDataplanePath(p SCION, auths snet.EpicAuths) (*EPIC, error) {
	if !auths.SupportsEpic() {
		return &EPIC{}, serrors.New("EPIC not supported")
	}
	epicPath := &EPIC{
		AuthPHVF: append([]byte(nil), auths.AuthPHVF...),
		AuthLHVF: append([]byte(nil), auths.AuthLHVF...),
		SCION:    append([]byte(nil), p.Raw...),
	}
	return epicPath, nil
}

func (e *EPIC) SetPath(s *slayers.SCION) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// XXX(roosd): This is not optimal regarding allocations etc. But it should
	// serve as an example.
	var sp scion.Raw
	if err := sp.DecodeFromBytes(e.SCION); err != nil {
		return err
	}

	info, err := sp.GetInfoField(0)
	if err != nil {
		return err
	}

	// Calculate packet ID.
	tsInfo := time.Unix(int64(info.Timestamp), 0)
	timestamp, err := libepic.CreateTimestamp(tsInfo, time.Now())
	if err != nil {
		return err
	}
	e.counter += 1
	pktID := epic.PktID{
		Timestamp: timestamp,
		Counter:   e.counter,
	}

	// Calculate HVFs.
	phvf, err := libepic.CalcMac(e.AuthPHVF, pktID, s, info.Timestamp, nil)
	if err != nil {
		return err
	}
	lhvf, err := libepic.CalcMac(e.AuthLHVF, pktID, s, info.Timestamp, nil)
	if err != nil {
		return err
	}

	ep := &epic.Path{
		PktID:     pktID,
		PHVF:      phvf[:epic.HVFLen],
		LHVF:      lhvf[:epic.HVFLen],
		ScionPath: &sp,
	}
	s.Path, s.PathType = ep, ep.Type()
	return nil
}
