// Copyright 2025 ETH Zurich
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

package verifier

import (
	"context"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
)

// AcceptAllVerifier accepts all path segments without verification.
// It is only intended for testing purposes.
type AcceptAllVerifier struct{}

func (AcceptAllVerifier) Verify(
	ctx context.Context, signedMsg *crypto.SignedMessage,
	associatedData ...[]byte,
) (*signed.Message, error) {
	return nil, nil
}

func (v AcceptAllVerifier) WithServer(net.Addr) Verifier {
	return v
}

func (v AcceptAllVerifier) WithIA(addr.IA) Verifier {
	return v
}

func (v AcceptAllVerifier) WithValidity(cppki.Validity) Verifier {
	return v
}
