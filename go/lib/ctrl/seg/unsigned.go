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

package seg

import (
	"github.com/scionproto/scion/go/lib/ctrl/seg/extensions/epic"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type UnsignedExtensions struct {
	// EpicDetached contains the detachable epic authenticators. It is nil
	// if it was detached (or never added).
	EpicDetached *epic.Detached
}

func UnsignedExtensionsFromPB(ue *cppb.PathSegmentUnsignedExtensions) UnsignedExtensions {
	if ue == nil {
		return UnsignedExtensions{}
	}
	return UnsignedExtensions{
		EpicDetached: epic.DetachedFromPB(ue.Epic),
	}
}

func UnsignedExtensionsToPB(ue UnsignedExtensions) *cppb.PathSegmentUnsignedExtensions {
	if ue.EpicDetached == nil {
		return nil
	}
	return &cppb.PathSegmentUnsignedExtensions{
		Epic: epic.DetachedToPB(ue.EpicDetached),
	}
}

// checkUnsignedExtensions checks whether the unsigned extensions are consistent with the
// signed hash. Furthermore, an unsigned extension is not valid if it is present in the
// ASEntry, but the corresponding hash is not.
func checkUnsignedExtensions(ue *UnsignedExtensions, e *Extensions) error {
	if ue == nil || e == nil {
		return serrors.New("invalid input to checkUnsignedExtensions")
	}

	// If unsigned extension is present but hash is not, return error
	// EPIC:
	epicDetached := (ue.EpicDetached != nil)
	epicDigest := (e.Digests != nil && len(e.Digests.Epic.Digest) != 0)
	if epicDetached && !epicDigest {
		return serrors.New("epic authenticators present, but hash is not")
	}

	// Check consistency (digest extension contains correct hash)
	// EPIC:
	if epicDetached && epicDigest {
		input, err := ue.EpicDetached.DigestInput()
		if err != nil {
			return err
		}
		if err := e.Digests.Epic.Validate(input); err != nil {
			return err
		}
	}
	return nil
}
