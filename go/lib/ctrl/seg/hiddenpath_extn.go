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

// This file contains the Go representation of a hidden path segment extension
// used to distinguish hidden segments from regular segments.

package seg

import (
	"fmt"

	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*HiddenPathSegExtn)(nil)

type HiddenPathSegExtn struct {
	Set bool
}

func NewHiddenPathSegExtn() *HiddenPathSegExtn {
	return &HiddenPathSegExtn{Set: true}
}

func (hpExt *HiddenPathSegExtn) ProtoId() proto.ProtoIdType {
	return proto.HiddenPathSegExtn_TypeID
}

func (hpExt *HiddenPathSegExtn) String() string {
	if hpExt == nil {
		return fmt.Sprintf("%v", false)
	}
	return fmt.Sprintf("%v", hpExt.Set)
}
