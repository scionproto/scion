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

package certs

import (
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/keys"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

type issMeta struct {
	Cert    cert.SignedIssuer
	Version scrypto.Version
}

type issGen struct {
	Dirs    pkicmn.Dirs
	Version scrypto.Version
}

func (g issGen) Run(asMap pkicmn.ASMap) error {
	cfgs, err := loader{Dirs: g.Dirs, Version: g.Version}.LoadIssuerConfigs(asMap)
	if err != nil {
		return serrors.WrapStr("unable to load issuer certifcate configs", err)
	}
	certs, err := g.generateAll(cfgs)
	if err != nil {
		return serrors.WrapStr("unable to generate issuer certificates", err)
	}
	if err := g.signAll(certs, cfgs); err != nil {
		return serrors.WrapStr("unable to sign issuer certificates", err)
	}
	if err := g.verify(certs); err != nil {
		return serrors.WrapStr("unable to verify issuer certificates", err)
	}
	if err := g.createDirs(certs); err != nil {
		return serrors.WrapStr("unable to create output directories", err)
	}
	if err := g.write(certs); err != nil {
		return serrors.WrapStr("unable to write issuer certificates", err)
	}
	return nil
}

func (g issGen) generateAll(cfgs map[addr.IA]conf.Issuer) (map[addr.IA]issMeta, error) {
	certs := make(map[addr.IA]issMeta)
	for ia, cfg := range cfgs {
		signed, err := g.generate(ia, cfg)
		if err != nil {
			return nil, serrors.WrapStr("unable to generate issuer certificate", err,
				"ia", ia, "version", cfg.Version)
		}
		certs[ia] = signed
	}
	return certs, nil
}

func (g issGen) generate(ia addr.IA, cfg conf.Issuer) (issMeta, error) {
	pubKeys, err := g.loadPubKeys(ia, cfg)
	if err != nil {
		return issMeta{}, serrors.WrapStr("unable to load all public keys", err)
	}
	enc, err := cert.EncodeIssuer(newIssuerCert(ia, cfg, pubKeys))
	if err != nil {
		return issMeta{}, serrors.WrapStr("unable to encode issuer certificate", err)
	}
	meta := issMeta{
		Cert:    cert.SignedIssuer{Encoded: enc},
		Version: cfg.Version,
	}
	return meta, nil
}

func (g issGen) loadPubKeys(ia addr.IA, cfg conf.Issuer) (map[cert.KeyType]keyconf.Key, error) {
	keys := make(map[cert.KeyType]keyconf.Key)
	ids := map[cert.KeyType]keyconf.ID{
		cert.IssuingKey: {
			IA:      ia,
			Usage:   keyconf.IssCertSigningKey,
			Version: *cfg.IssuingGrantKeyVersion,
		},
	}
	if cfg.RevocationKeyVersion != nil {
		ids[cert.RevocationKey] = keyconf.ID{
			IA:      ia,
			Usage:   keyconf.IssRevocationKey,
			Version: *cfg.RevocationKeyVersion,
		}
	}
	for keyType, id := range ids {
		key, err := g.loadPubKey(id)
		if err != nil {
			return nil, serrors.WithCtx(err, "usage", id.Usage)
		}
		keys[keyType] = key
	}
	return keys, nil
}

func (g issGen) loadPubKey(id keyconf.ID) (keyconf.Key, error) {
	key, fromPriv, err := keys.LoadPublicKey(g.Dirs.Out, id)
	if err != nil {
		return keyconf.Key{}, err
	}
	if fromPriv {
		pkicmn.QuietPrint("Using private %s key for %s\n", id.Usage, id.IA)
		return key, nil
	}
	pkicmn.QuietPrint("Using public %s key for %s\n", id.Usage, id.IA)
	return key, nil
}

func (g issGen) signAll(protos map[addr.IA]issMeta, cfgs map[addr.IA]conf.Issuer) error {
	for ia, meta := range protos {
		var err error
		if meta.Cert, err = g.sign(ia, cfgs[ia], meta.Cert); err != nil {
			return serrors.WrapStr("unable to sign issuer certificate", err, "ia", ia)
		}
		protos[ia] = meta
	}
	return nil
}

func (g issGen) sign(ia addr.IA, cfg conf.Issuer,
	signed cert.SignedIssuer) (cert.SignedIssuer, error) {

	file := conf.TRCFile(g.Dirs.Root, ia.I, cfg.TRCVersion)
	trcCfg, err := conf.LoadTRC(file)
	if err != nil {
		return cert.SignedIssuer{}, serrors.WrapStr("unable to load TRC config", err, "file", file)
	}
	primary, ok := trcCfg.PrimaryASes[ia.A]
	if !ok || !primary.Attributes.Contains(trc.Issuing) || primary.IssuingGrantKeyVersion == nil {
		return cert.SignedIssuer{}, serrors.New("not an issuing AS")
	}
	id := keyconf.ID{
		IA:      ia,
		Usage:   keyconf.TRCIssuingGrantKey,
		Version: *primary.IssuingGrantKeyVersion,
	}
	key, err := keyconf.LoadKeyFromFile(keys.PrivateFile(g.Dirs.Out, id), keyconf.PrivateKey, id)
	if err != nil {
		return cert.SignedIssuer{}, serrors.WrapStr("unable to load issuing key", err, "file", file)
	}
	protected := cert.ProtectedIssuer{
		Algorithm:  key.Algorithm,
		TRCVersion: cfg.TRCVersion,
	}
	if signed.EncodedProtected, err = cert.EncodeProtectedIssuer(protected); err != nil {
		return cert.SignedIssuer{}, serrors.WrapStr("unable to encode protected", err)
	}
	signed.Signature, err = scrypto.Sign(signed.SigInput(), key.Bytes, key.Algorithm)
	if err != nil {
		return cert.SignedIssuer{}, serrors.WrapStr("unable to sign issuer certificate", err)
	}
	return signed, nil
}

func (g issGen) verify(certs map[addr.IA]issMeta) error {
	v := verifier{Dirs: g.Dirs}
	for ia, meta := range certs {
		raw, err := cert.EncodeSignedIssuer(meta.Cert)
		if err != nil {
			return serrors.WrapStr("unable to encode signed issuer certificate", err)
		}
		if err := v.VerifyIssuer(raw); err != nil {
			return serrors.WrapStr("unable to verify issuer certificate", err, "ia", ia)
		}
	}
	return nil
}

func (g issGen) createDirs(certs map[addr.IA]issMeta) error {
	for ia := range certs {
		if err := os.MkdirAll(Dir(g.Dirs.Out, ia), 0755); err != nil {
			return serrors.WrapStr("unable to make certs directory", err, "ia", ia)
		}
	}
	return nil
}

func (g issGen) write(certs map[addr.IA]issMeta) error {
	for ia, meta := range certs {
		raw, err := cert.EncodeSignedIssuer(meta.Cert)
		if err != nil {
			return serrors.WrapStr("unable to encode signed issuer certificate", err)
		}
		file := IssuerFile(g.Dirs.Out, ia, meta.Version)
		if err := pkicmn.WriteToFile(raw, file, 0644); err != nil {
			return serrors.WrapStr("unable to write signed issuer certificate", err, "file", file)
		}
	}
	return nil
}

func newIssuerCert(ia addr.IA, cfg conf.Issuer, pubKeys map[cert.KeyType]keyconf.Key) *cert.Issuer {

	val := cfg.Validity.Eval(time.Now())
	c := &cert.Issuer{
		Base: cert.Base{
			Subject:                    ia,
			Version:                    cfg.Version,
			FormatVersion:              1,
			Description:                cfg.Description,
			OptionalDistributionPoints: cfg.OptDistPoints,
			Validity:                   &val,
			Keys:                       translateKeys(pubKeys),
		},
		Issuer: cert.IssuerTRC{
			TRCVersion: cfg.TRCVersion,
		},
	}
	return c
}
