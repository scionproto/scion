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

package xtrust

import (
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/proto"
)

// Signer is a simple implementation of infra.Signer.
type Signer struct {
	Cfg      infra.SignerMeta
	SignType proto.SignType
	Key      []byte
}

// Sign signs the message.
func (b *Signer) Sign(msg []byte) (*proto.SignS, error) {
	var err error
	sign := proto.NewSignS(b.SignType, b.Cfg.Src.Pack())
	sign.Signature, err = scrypto.Sign(sign.SigInput(msg, true), b.Key, b.Cfg.Algo)
	return sign, err
}

// Meta returns the meta data the signer uses when signing.
func (b *Signer) Meta() infra.SignerMeta {
	return b.Cfg
}
