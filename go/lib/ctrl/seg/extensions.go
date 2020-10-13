// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seg

import (
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type Extensions struct {
	HiddenPath HiddenPathExtension
	StaticInfo *StaticInfoExtension
}

func extensionsFromPB(pb *cppb.PathSegmentExtensions) (Extensions, error) {
	if pb == nil {
		return Extensions{}, nil
	}

	hiddenPath := HiddenPathExtension{
		IsHidden: pb.HiddenPath != nil && pb.HiddenPath.IsHidden,
	}

	staticInfo, err := staticInfoExtensionFromPB(pb.StaticInfo)
	if err != nil {
		return Extensions{}, err
	}

	return Extensions{
		HiddenPath: hiddenPath,
		StaticInfo: staticInfo,
	}, nil
}

func extensionsToPB(ext Extensions) *cppb.PathSegmentExtensions {
	var hiddenPath *cppb.HiddenPathExtension
	if ext.HiddenPath.IsHidden {
		hiddenPath = &cppb.HiddenPathExtension{IsHidden: true}
	}
	staticInfo := staticInfoExtensionToPB(ext.StaticInfo)

	if hiddenPath != nil || staticInfo != nil {
		return &cppb.PathSegmentExtensions{
			HiddenPath: hiddenPath,
			StaticInfo: staticInfo,
		}
	}
	return nil
}
