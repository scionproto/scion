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

package trust

import (
	"bytes"
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

// KeyRing provides different private keys.
type KeyRing interface {
	// PrivateKey returns the private key for the given usage and version. If it
	// is not in the key ring, an error is returned.
	PrivateKey(usage keyconf.Usage, version scrypto.KeyVersion) (keyconf.Key, error)
}

// SignerConf holds the configuration of a signer.
type SignerConf struct {
	ChainVer scrypto.Version
	TRCVer   scrypto.Version
	Validity scrypto.Validity
	Key      keyconf.Key
}

// Validate validates that the signer config is valid.
func (cfg SignerConf) Validate() error {
	switch {
	case cfg.ChainVer.IsLatest():
		return serrors.New("chain version is latest")
	case cfg.TRCVer.IsLatest():
		return serrors.New("TRC version is latest")
	case cfg.Key.IA.IsWildcard():
		return serrors.New("wildcard IA")
	case cfg.Key.Type != keyconf.PrivateKey:
		return serrors.New("wrong key type", "type", cfg.Key.Type)
	}
	if _, err := signTypeFromAlgo(cfg.Key.Algorithm); err != nil {
		return err
	}
	return nil
}

// Signer is used to sign control plane data authenticated by certificate chains.
type Signer struct {
	cfg      SignerConf
	signType proto.SignType
	src      []byte
}

// NewSigner constructs a new signer.
func NewSigner(cfg SignerConf) (*Signer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	signType, _ := signTypeFromAlgo(cfg.Key.Algorithm)
	src := ctrl.SignSrcDef{
		IA:       cfg.Key.IA,
		ChainVer: cfg.ChainVer,
		TRCVer:   cfg.TRCVer,
	}
	s := &Signer{
		signType: signType,
		src:      src.Pack(),
		cfg:      cfg,
	}
	return s, nil
}

// Sign signs the message.
func (s *Signer) Sign(msg []byte) (*proto.SignS, error) {
	var err error
	l := metrics.SignerLabels{}
	sign := proto.NewSignS(s.signType, append(s.src[:0:0], s.src...))
	sign.Signature, err = scrypto.Sign(sign.SigInput(msg, true),
		s.cfg.Key.Bytes, s.cfg.Key.Algorithm)
	if err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, err
	}
	metrics.Signer.Sign(l.WithResult(metrics.Success)).Inc()
	return sign, nil
}

// Meta returns the meta data the signer uses when signing.
func (s *Signer) Meta() infra.SignerMeta {
	return infra.SignerMeta{
		Src: ctrl.SignSrcDef{
			IA:       s.cfg.Key.IA,
			ChainVer: s.cfg.ChainVer,
			TRCVer:   s.cfg.TRCVer,
		},
		ExpTime: s.cfg.Validity.NotAfter.Time,
		Algo:    s.cfg.Key.Algorithm,
	}
}

// SignerGen generates signers based on the certificate chains and keys that are
// available.
type SignerGen struct {
	IA       addr.IA
	KeyRing  KeyRing
	Provider CryptoProvider
}

// Signer returns the active signer.
func (g *SignerGen) Signer(ctx context.Context) (*Signer, error) {
	l := metrics.SignerLabels{}
	raw, err := g.Provider.GetRawChain(ctx, ChainID{IA: g.IA, Version: scrypto.LatestVer},
		infra.ChainOpts{})
	if err != nil {
		metrics.Signer.Generate(l.WithResult(errToLabel(err))).Inc()
		return nil, serrors.WrapStr("error fetching latest chain", err, "ia", g.IA)
	}
	dec, err := decoded.DecodeChain(raw)
	if err != nil {
		metrics.Signer.Generate(l.WithResult(errToLabel(err))).Inc()
		return nil, err
	}
	priv, err := g.KeyRing.PrivateKey(keyconf.ASSigningKey, dec.AS.Keys[cert.SigningKey].KeyVersion)
	if err != nil {
		metrics.Signer.Generate(l.WithResult(metrics.ErrKey)).Inc()
		return nil, serrors.WrapStr("private key not found", err, "chain", dec,
			"key_version", dec.AS.Keys[cert.SigningKey].KeyVersion)
	}
	pub, err := scrypto.GetPubKey(priv.Bytes, priv.Algorithm)
	if err != nil {
		metrics.Signer.Generate(l.WithResult(metrics.ErrKey)).Inc()
		return nil, serrors.WrapStr("unable to compute public key", err, "chain", dec,
			"key_version", dec.AS.Keys[cert.SigningKey].KeyVersion)
	}
	if !bytes.Equal(dec.AS.Keys[cert.SigningKey].Key, pub) {
		metrics.Signer.Generate(l.WithResult(metrics.ErrKey)).Inc()
		return nil, serrors.WrapStr("public key does not match", err, "chain", dec,
			"key_version", dec.AS.Keys[cert.SigningKey].KeyVersion)
	}
	trc, err := g.Provider.GetTRC(ctx, TRCID{ISD: g.IA.I, Version: scrypto.LatestVer},
		infra.TRCOpts{})
	if err != nil {
		metrics.Signer.Generate(l.WithResult(errToLabel(err))).Inc()
		return nil, serrors.WrapStr("unable to get latest local TRC", err, "isd", g.IA.I)
	}
	metrics.Signer.Generate(l.WithResult(metrics.Success)).Inc()
	return NewSigner(SignerConf{
		ChainVer: dec.AS.Version,
		TRCVer:   trc.Version,
		Validity: *dec.AS.Validity,
		Key:      priv,
	})
}

func signTypeFromAlgo(algo string) (proto.SignType, error) {
	switch algo {
	case scrypto.Ed25519:
		return proto.SignType_ed25519, nil
	default:
		return proto.SignType_none, serrors.New("unsupported signing algorithm", "algo", algo)
	}
}
