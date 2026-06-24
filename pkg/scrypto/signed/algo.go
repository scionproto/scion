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
	"crypto/mldsa"
	"fmt"

	"github.com/scionproto/scion/pkg/private/serrors"
	pbcrypto "github.com/scionproto/scion/pkg/proto/crypto"
)

// List of supported signature algorithms
const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	MLDSA44
	MLDSA65
	MLDSA87
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
	case *mldsa.PublicKey:
		switch p.Parameters() {
		case mldsa.MLDSA44():
			return MLDSA44, nil
		case mldsa.MLDSA65():
			return MLDSA65, nil
		case mldsa.MLDSA87():
			return MLDSA87, nil
		default:
			return 0, serrors.New("mldsa: unsupported parameter set")
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
	case pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_44:
		return MLDSA44
	case pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65:
		return MLDSA65
	case pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_87:
		return MLDSA87
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
	case MLDSA44:
		return pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_44
	case MLDSA65:
		return pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65
	case MLDSA87:
		return pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_87
	default:
		return pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED
	}
}

const (
	unknownPublicKeyAlgorithm publicKeyAlgorithm = iota //nolint:golint,deadcode,varcheck
	pkECDSA
	pkMLDSA
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
	MLDSA44:         {name: "ML-DSA-44", pubKeyAlgo: pkMLDSA, hash: 0},
	MLDSA65:         {name: "ML-DSA-65", pubKeyAlgo: pkMLDSA, hash: 0},
	MLDSA87:         {name: "ML-DSA-87", pubKeyAlgo: pkMLDSA, hash: 0},
}

func (a SignatureAlgorithm) String() string {
	return signatureAlgorithmDetails[a].name
}
