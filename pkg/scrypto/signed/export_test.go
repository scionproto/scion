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

package signed

import (
	"crypto"
)

const (
	// PurePureEd25519 is used to check signature input creation is correct.
	// Officially, we do not yet support ed25519.
	PureEd25519 SignatureAlgorithm = 1 << 16
	pkEd25519   publicKeyAlgorithm = 1 << 16
)

func init() {
	signatureAlgorithmDetails[PureEd25519] = struct {
		name       string
		pubKeyAlgo publicKeyAlgorithm
		hash       crypto.Hash
	}{
		name:       "Ed25519",
		pubKeyAlgo: pkEd25519,
		hash:       0,
	}
}

var ComputeSignatureInput = computeSignatureInput
