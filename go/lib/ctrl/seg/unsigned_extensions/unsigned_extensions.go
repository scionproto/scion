// Copyright 2020 ETH Zurich
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

package unsigned_extensions

import (
	"github.com/scionproto/scion/go/lib/ctrl/seg/unsigned_extensions/epic_detached"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type UnsignedExtensions struct {
	// EpicDetached contains the detachable epic authenticators. It is nil
	// if it was detached (or never added).
	EpicDetached *epic_detached.EpicDetached
}

func UnsignedExtensionsFromPB(ue *cppb.PathSegmentUnsignedExtensions) UnsignedExtensions {
	if ue == nil {
		return UnsignedExtensions{}
	}
	ed := epic_detached.EpicDetachedFromPB(ue.EpicDetachedExtension)
	return UnsignedExtensions{
		EpicDetached: ed,
	}
}

func UnsignedExtensionsToPB(ue UnsignedExtensions) *cppb.PathSegmentUnsignedExtensions {
	if ue.EpicDetached == nil {
		return &cppb.PathSegmentUnsignedExtensions{}
	}
	return &cppb.PathSegmentUnsignedExtensions{
		EpicDetachedExtension: epic_detached.EpicDetachedToPB(ue.EpicDetached),
	}
}
