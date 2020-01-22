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
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/keys"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

type chainMeta struct {
	Chain   cert.Chain
	Version scrypto.Version
}

type chainGen struct {
	Dirs    pkicmn.Dirs
	Version scrypto.Version
}

func (g chainGen) Run(asMap pkicmn.ASMap) error {
	cfgs, err := loader{Dirs: g.Dirs, Version: g.Version}.LoadASConfigs(asMap)
	if err != nil {
		return serrors.WrapStr("unable to load AS certificate configs", err)
	}
	certs, err := g.generateAll(cfgs)
	if err != nil {
		return serrors.WrapStr("unable to generate AS certificates", err)
	}
	if err := g.signAll(certs, cfgs); err != nil {
		return serrors.WrapStr("unable to sign AS certificates", err)
	}
	if err := g.verify(certs); err != nil {
		return serrors.WrapStr("unable to verify AS certificates", err)
	}
	if err := g.createDirs(certs); err != nil {
		return serrors.WrapStr("unable to create output directories", err)
	}
	if err := g.write(certs); err != nil {
		return serrors.WrapStr("unable to write AS certificates", err)
	}
	return nil
}

func (g chainGen) generateAll(cfgs map[addr.IA]conf.AS) (map[addr.IA]chainMeta, error) {
	certs := make(map[addr.IA]chainMeta)
	for ia, cfg := range cfgs {
		chain, err := g.generate(ia, cfg)
		if err != nil {
			return nil, serrors.WrapStr("unable to generate issuer certificate", err,
				"ia", ia, "version", cfg.Version)
		}
		certs[ia] = chain
	}
	return certs, nil
}

func (g chainGen) generate(ia addr.IA, cfg conf.AS) (chainMeta, error) {
	pubKeys, err := g.loadPubKeys(ia, cfg)
	if err != nil {
		return chainMeta{}, serrors.WrapStr("unable to load all public keys", err)
	}
	enc, err := cert.EncodeAS(newASCert(ia, cfg, pubKeys))
	if err != nil {
		return chainMeta{}, serrors.WrapStr("unable to encode AS certificate", err)
	}
	file := IssuerFile(g.Dirs.Out, cfg.IssuerIA, cfg.IssuerCertVersion)
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return chainMeta{}, serrors.WrapStr("unable to read issuer certificate", err, "file", file)
	}
	issuer, err := cert.ParseSignedIssuer(raw)
	if err != nil {
		return chainMeta{}, serrors.WrapStr("unable to parse issuer certificate", err, "file", file)
	}
	meta := chainMeta{
		Chain: cert.Chain{
			Issuer: issuer,
			AS:     cert.SignedAS{Encoded: enc},
		},
		Version: cfg.Version,
	}
	return meta, nil
}

func (g chainGen) loadPubKeys(ia addr.IA, cfg conf.AS) (map[cert.KeyType]keyconf.Key, error) {
	keys := make(map[cert.KeyType]keyconf.Key)
	type meta struct {
		Usage   keyconf.Usage
		Version scrypto.KeyVersion
	}
	load := map[cert.KeyType]keyconf.ID{
		cert.SigningKey: {
			IA:      ia,
			Version: *cfg.SigningKeyVersion,
			Usage:   keyconf.ASSigningKey,
		},
		cert.EncryptionKey: {
			IA:      ia,
			Version: *cfg.EncryptionKeyVersion,
			Usage:   keyconf.ASDecryptionKey,
		},
	}
	if cfg.RevocationKeyVersion != nil {
		load[cert.RevocationKey] = keyconf.ID{
			IA:      ia,
			Version: *cfg.RevocationKeyVersion,
			Usage:   keyconf.ASRevocationKey,
		}
	}
	for keyType, id := range load {
		key, err := g.loadPubKey(id)
		if err != nil {
			return nil, serrors.WrapStr("unable to load key", err, "usage", id.Usage)
		}
		keys[keyType] = key
	}
	return keys, nil
}

func (g chainGen) loadPubKey(id keyconf.ID) (keyconf.Key, error) {
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

func (g chainGen) signAll(protos map[addr.IA]chainMeta, cfgs map[addr.IA]conf.AS) error {
	for ia, meta := range protos {
		var err error
		if meta.Chain, err = g.sign(cfgs[ia], meta.Chain); err != nil {
			return serrors.WrapStr("unable to sign AS certificate", err, "ia", ia)
		}
		protos[ia] = meta
	}
	return nil
}

func (g chainGen) sign(cfg conf.AS, chain cert.Chain) (cert.Chain, error) {
	file := conf.IssuerFile(g.Dirs.Root, cfg.IssuerIA, cfg.IssuerCertVersion)
	issCfg, err := conf.LoadIssuer(file)
	if err != nil {
		return cert.Chain{}, serrors.WrapStr("unable to load issuer config", err, "file", file)
	}
	file = filepath.Join(keys.PrivateDir(g.Dirs.Out, cfg.IssuerIA),
		keyconf.PrivateKeyFile(keyconf.IssCertSigningKey, *issCfg.IssuingGrantKeyVersion))
	id := keyconf.ID{
		IA:      cfg.IssuerIA,
		Usage:   keyconf.IssCertSigningKey,
		Version: *issCfg.IssuingGrantKeyVersion,
	}
	key, err := keyconf.LoadKeyFromFile(file, keyconf.PrivateKey, id)
	if err != nil {
		return cert.Chain{}, serrors.WrapStr("unable to load issuing key", err, "file", file)
	}
	protected := cert.ProtectedAS{
		Algorithm:          key.Algorithm,
		IA:                 cfg.IssuerIA,
		CertificateVersion: cfg.IssuerCertVersion,
	}
	if chain.AS.EncodedProtected, err = cert.EncodeProtectedAS(protected); err != nil {
		return cert.Chain{}, serrors.WrapStr("unable to encode protected", err)
	}
	chain.AS.Signature, err = scrypto.Sign(chain.AS.SigInput(), key.Bytes, key.Algorithm)
	if err != nil {
		return cert.Chain{}, serrors.WrapStr("unable to sign issuer certificate", err)
	}
	return chain, nil
}

func (g chainGen) verify(certs map[addr.IA]chainMeta) error {
	v := verifier{Dirs: g.Dirs}
	for ia, meta := range certs {
		raw, err := meta.Chain.MarshalJSON()
		if err != nil {
			return serrors.WrapStr("unable to encode certificate chain", err)
		}
		if err := v.VerifyChain(raw); err != nil {
			return serrors.WrapStr("unable to verify certificate chain", err, "ia", ia)
		}
	}
	return nil
}

func (g chainGen) createDirs(certs map[addr.IA]chainMeta) error {
	for ia := range certs {
		if err := os.MkdirAll(Dir(g.Dirs.Out, ia), 0755); err != nil {
			return serrors.WrapStr("unable to make certs directory", err, "ia", ia)
		}
	}
	return nil
}

func (g chainGen) write(certs map[addr.IA]chainMeta) error {
	for ia, meta := range certs {
		raw, err := meta.Chain.MarshalJSON()
		if err != nil {
			return serrors.WrapStr("unable to encode signed issuer certificate", err)
		}
		file := ASFile(g.Dirs.Out, ia, meta.Version)
		if err := pkicmn.WriteToFile(raw, file, 0644); err != nil {
			return serrors.WrapStr("unable to write signed issuer certificate", err, "file", file)
		}
	}
	return nil
}

func newASCert(ia addr.IA, cfg conf.AS, pubKeys map[cert.KeyType]keyconf.Key) *cert.AS {
	val := cfg.Validity.Eval(time.Now())
	c := &cert.AS{
		Base: cert.Base{
			Subject:                    ia,
			Version:                    cfg.Version,
			FormatVersion:              1,
			Description:                cfg.Description,
			OptionalDistributionPoints: cfg.OptDistPoints,
			Validity:                   &val,
			Keys:                       translateKeys(pubKeys),
		},
		Issuer: cert.IssuerCertID{
			IA:                 cfg.IssuerIA,
			CertificateVersion: cfg.IssuerCertVersion,
		},
	}
	return c
}
