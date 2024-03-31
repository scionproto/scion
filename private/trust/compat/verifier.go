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

package compat

import (
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	infra "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/trust"
)

// Verifier wraps the trust Verifier to implement the infra.Verifier interface.
type Verifier struct {
	trust.Verifier
}

func (v Verifier) WithIA(ia addr.IA) infra.Verifier {
	v.BoundIA = ia
	return v
}

func (v Verifier) WithServer(server net.Addr) infra.Verifier {
	v.BoundServer = server
	return v
}

func (v Verifier) WithValidity(validity cppki.Validity) infra.Verifier {
	v.BoundValidity = validity
	return v
}
