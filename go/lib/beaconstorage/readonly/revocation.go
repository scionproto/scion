// Copyright 2019 Anapaya Systems
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

package readonly

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
)

// Revocation is a read-only wrapper for SignedRevInfo to avoid awkward
// error handling for already validated data. The embedded signed
// revocation info must not be modified or the is allowed to panic.
type Revocation struct {
	*path_mgmt.SignedRevInfo
}

// NewRevocation ensures that the revocation info is parsed and creates
// a read-only wrapper. After this call, the signed revocation info must
// not be modified.
func NewRevocation(s *path_mgmt.SignedRevInfo) (Revocation, error) {
	if _, err := s.RevInfo(); err != nil {
		return Revocation{}, err
	}
	return Revocation{s}, nil
}

// NewRevocationFromRaw ensures that the revocation info is parsed and
// creates a read-only wrapper. After this call, the signed revocation info
// must not be modified.
func NewRevocationFromRaw(b common.RawBytes) (Revocation, error) {
	s, err := path_mgmt.NewSignedRevInfoFromRaw(b)
	if err != nil {
		return Revocation{}, err
	}
	return NewRevocation(s)
}

// RevInfo returns the parsed revocation info. If the signed revocation
// info has been modified, this might panic.
func (r Revocation) RevInfo() *path_mgmt.RevInfo {
	revInfo, err := r.SignedRevInfo.RevInfo()
	if err != nil {
		panic(fmt.Sprintf("Modified read-only signed revocation info err=%s", err))
	}
	return revInfo
}
