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
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/scionproto/scion/go/lib/serrors"
	pbcrypto "github.com/scionproto/scion/go/pkg/proto/crypto"
)

// List of supported signature algorithms
const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
)

type SignatureAlgorithm int

// SelectSignatureAlgorithm selects the signature algorithm based on the public
// key algorithm.
func SelectSignatureAlgorithm(pub crypto.PublicKey) (SignatureAlgorithm, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256():
			return ECDSAWithSHA256, nil
		case elliptic.P384():
			return ECDSAWithSHA384, nil
		case elliptic.P521():
			return ECDSAWithSHA512, nil
		default:
			return 0, serrors.New("ecdsa: unsupported curve", "curve", p.Curve)
		}
	default:
		return 0, serrors.New("unsupported public key algorithm", "type", fmt.Sprintf("%T", pub))
	}
}

func signatureAlgorithmFromPB(a pbcrypto.SignatureAlgorithm) SignatureAlgorithm {
	switch a {
	case pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256:
		return ECDSAWithSHA256
	case pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384:
		return ECDSAWithSHA384
	case pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512:
		return ECDSAWithSHA512
	default:
		return UnknownSignatureAlgorithm
	}
}

func (a SignatureAlgorithm) toPB() pbcrypto.SignatureAlgorithm {
	switch a {
	case ECDSAWithSHA256:
		return pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256
	case ECDSAWithSHA384:
		return pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384
	case ECDSAWithSHA512:
		return pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512
	default:
		return pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED
	}
}

const (
	unknownPublicKeyAlgorithm publicKeyAlgorithm = iota
	pkECDSA
)

type publicKeyAlgorithm int

var signatureAlgorithmDetails = map[SignatureAlgorithm]struct {
	name       string
	pubKeyAlgo publicKeyAlgorithm
	hash       crypto.Hash
}{
	ECDSAWithSHA256: {name: "ECDSA-SHA256", pubKeyAlgo: pkECDSA, hash: crypto.SHA256},
	ECDSAWithSHA384: {name: "ECDSA-SHA384", pubKeyAlgo: pkECDSA, hash: crypto.SHA384},
	ECDSAWithSHA512: {name: "ECDSA-SHA512", pubKeyAlgo: pkECDSA, hash: crypto.SHA512},
}

func (a SignatureAlgorithm) String() string {
	return signatureAlgorithmDetails[a].name
}
