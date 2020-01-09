// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package trust

import (
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/proto"
)

const (
	// MaxPldAge indicates the maximum age of a control payload signature.
	MaxPldAge = 2 * time.Second
	// MaxInFuture indicates the maximum time a timestamp may be in the future.
	MaxInFuture = time.Second
)

var _ infra.Signer = (*BasicSigner)(nil)

// BasicSigner is a simple implementation of Signer.
type BasicSigner struct {
	meta      infra.SignerMeta
	signType  proto.SignType
	packedSrc []byte
	key       []byte
}

// NewBasicSigner creates a Signer that uses the supplied meta to sign
// messages.
func NewBasicSigner(key []byte, meta infra.SignerMeta) (*BasicSigner, error) {
	if meta.Src.IA.IsWildcard() {
		return nil, common.NewBasicError("IA must not contain wildcard", nil, "ia", meta.Src.IA)
	}
	if meta.Src.ChainVer.IsLatest() {
		return nil, common.NewBasicError("ChainVer must be valid", nil, "ver", meta.Src.ChainVer)
	}
	if meta.Src.TRCVer.IsLatest() {
		return nil, common.NewBasicError("TRCVer must be valid", nil, "ver", meta.Src.TRCVer)
	}
	signer := &BasicSigner{
		meta:      meta,
		key:       key,
		packedSrc: meta.Src.Pack(),
	}
	switch meta.Algo {
	case scrypto.Ed25519:
		signer.signType = proto.SignType_ed25519
	default:
		return nil, common.NewBasicError("Unsupported signing algorithm", nil, "algo", meta.Algo)
	}
	return signer, nil
}

// Sign signs the message.
func (b *BasicSigner) Sign(msg []byte) (*proto.SignS, error) {
	var err error
	sign := proto.NewSignS(b.signType, append([]byte(nil), b.packedSrc...))
	sign.Signature, err = scrypto.Sign(sign.SigInput(msg, true), b.key, b.meta.Algo)
	return sign, err
}

// Meta returns the meta data the signer uses when signing.
func (b *BasicSigner) Meta() infra.SignerMeta {
	return b.meta
}
