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

package segment

import (
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/segment/extensions/digest"
	"github.com/scionproto/scion/pkg/segment/extensions/discovery"
	"github.com/scionproto/scion/pkg/segment/extensions/staticinfo"
)

type Extensions struct {
	HiddenPath HiddenPathExtension
	StaticInfo *staticinfo.Extension
	Discovery  *discovery.Extension
	Digests    *digest.Extension
}

func extensionsFromPB(pb *cppb.PathSegmentExtensions) (Extensions, error) {
	if pb == nil {
		return Extensions{}, nil
	}

	hiddenPath := HiddenPathExtension{
		IsHidden: pb.HiddenPath != nil && pb.HiddenPath.IsHidden,
	}
	staticInfo := staticinfo.FromPB(pb.StaticInfo)
	discovery, err := discovery.FromPB(pb.Discovery)
	if err != nil {
		return Extensions{}, err
	}
	digest := digest.ExtensionFromPB(pb.Digests)
	return Extensions{
		HiddenPath: hiddenPath,
		StaticInfo: staticInfo,
		Discovery:  discovery,
		Digests:    digest,
	}, nil
}

func extensionsToPB(ext Extensions) *cppb.PathSegmentExtensions {
	var hiddenPath *cppb.HiddenPathExtension
	if ext.HiddenPath.IsHidden {
		hiddenPath = &cppb.HiddenPathExtension{IsHidden: true}
	}
	staticInfo := staticinfo.ToPB(ext.StaticInfo)
	discovery := discovery.ToPB(ext.Discovery)
	digest := digest.ExtensionToPB(ext.Digests)

	if hiddenPath != nil || staticInfo != nil || discovery != nil || digest != nil {
		return &cppb.PathSegmentExtensions{
			HiddenPath: hiddenPath,
			StaticInfo: staticInfo,
			Discovery:  discovery,
			Digests:    digest,
		}
	}
	return nil
}
