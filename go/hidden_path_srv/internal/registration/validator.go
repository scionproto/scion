// Copyright 2019 ETH Zurich
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

package registration

import (
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
)

const (
	ErrNoSegments   common.ErrMsg = "no segments"
	ErrMissingExtn  common.ErrMsg = "missing HiddenPathSeg extension"
	ErrWrongSegType common.ErrMsg = "segment must be an up- or down-segment"
	ErrUnknownGroup common.ErrMsg = "group not known to HPS"
	ErrNotRegistry  common.ErrMsg = "HPS is not a Registry of this group"
	ErrNotWriter    common.ErrMsg = "peer is not a writer of this group"
	ErrNotReader    common.ErrMsg = "peer is not a reader of this group"
)

var _ Validator = (*DefaultValidator)(nil)

// DefaultValidator validates hidden path registrations based on hidden path group configurations
type DefaultValidator struct {
	localIA addr.IA
	groups  map[hiddenpath.GroupId]*hiddenpath.Group
}

// NewDefaultValidator creates a new DefaultValidator
func NewDefaultValidator(localIA addr.IA,
	groups map[hiddenpath.GroupId]*hiddenpath.Group) *DefaultValidator {

	return &DefaultValidator{
		localIA: localIA,
		groups:  groups,
	}
}

// Validate validates a hpSegReg with regard to the provided HP Group
func (v *DefaultValidator) Validate(hpSegReg *path_mgmt.HPSegReg, peer addr.IA) error {
	id := hiddenpath.IdFromMsg(hpSegReg.GroupId)
	if err := v.checkGroupPermissions(id, peer); err != nil {
		return serrors.WrapStr("Group configuration error", err, "group", id)
	}
	if err := v.checkSegments(hpSegReg.Recs); err != nil {
		return serrors.WrapStr("Invalid hidden segment", err)
	}
	return nil
}

func (v *DefaultValidator) checkGroupPermissions(groupId hiddenpath.GroupId, peer addr.IA) error {
	group, ok := v.groups[groupId]
	if !ok {
		return ErrUnknownGroup
	}
	if !group.HasRegistry(v.localIA) {
		return ErrNotRegistry
	}
	if peer != group.Owner && !group.HasWriter(peer) {
		return ErrNotWriter
	}
	return nil
}

func (v *DefaultValidator) checkSegments(recs []*seg.Meta) error {
	for _, s := range recs {
		if !checkHiddenSegExtn(s) {
			return ErrMissingExtn
		}
		if s.Type != seg.TypeUp && s.Type != seg.TypeDown {
			return ErrWrongSegType
		}
	}
	return nil
}

func checkHiddenSegExtn(s *seg.Meta) bool {
	if s.Segment.MaxIdx() < 0 {
		return false
	}
	lastASEntry := s.Segment.ASEntries[s.Segment.MaxIdx()]
	return lastASEntry.Extensions.HiddenPath.IsHidden
}
