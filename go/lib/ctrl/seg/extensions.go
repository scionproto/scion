// Copyright 2020 Anapaya Systems
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
	"github.com/scionproto/scion/go/lib/ctrl/seg/extensions/digest"
	"github.com/scionproto/scion/go/lib/ctrl/seg/extensions/staticinfo"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type Extensions struct {
	HiddenPath HiddenPathExtension
	StaticInfo *staticinfo.Extension
	Digests    *digest.Extension
}

func extensionsFromPB(pb *cppb.PathSegmentExtensions) Extensions {
	if pb == nil {
		return Extensions{}
	}

	hiddenPath := HiddenPathExtension{
		IsHidden: pb.HiddenPath != nil && pb.HiddenPath.IsHidden,
	}
	staticInfo := staticinfo.FromPB(pb.StaticInfo)
	digest := digest.ExtensionFromPB(pb.Digests)
	return Extensions{
		HiddenPath: hiddenPath,
		StaticInfo: staticInfo,
		Digests:    digest,
	}
}

func extensionsToPB(ext Extensions) *cppb.PathSegmentExtensions {
	var hiddenPath *cppb.HiddenPathExtension
	if ext.HiddenPath.IsHidden {
		hiddenPath = &cppb.HiddenPathExtension{IsHidden: true}
	}
	staticInfo := staticinfo.ToPB(ext.StaticInfo)
	digest := digest.ExtensionToPB(ext.Digests)

	if hiddenPath != nil || staticInfo != nil || digest != nil {
		return &cppb.PathSegmentExtensions{
			HiddenPath: hiddenPath,
			StaticInfo: staticInfo,
			Digests:    digest,
		}
	}
	return nil
}
