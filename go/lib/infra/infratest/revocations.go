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

// Package infratest contains utilities to work with infra types in tests.
package infratest

import (
	"testing"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/xtest"
)

// SignedRev creates a signed revocation from the given revInfo with the signer.
func SignedRev(t *testing.T,
	revInfo *path_mgmt.RevInfo, signer infra.Signer) *path_mgmt.SignedRevInfo {

	t.Helper()

	rawRevInfo, err := revInfo.Pack()
	xtest.FailOnErr(t, err)
	s, err := signer.Sign(rawRevInfo)
	xtest.FailOnErr(t, err)
	sRev, err := path_mgmt.NewSignedRevInfo(revInfo, s)
	xtest.FailOnErr(t, err)
	return sRev
}
