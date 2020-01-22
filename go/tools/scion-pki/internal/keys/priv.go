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

package keys

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

type privGen struct {
	Dirs pkicmn.Dirs
}

func (g privGen) Run(asMap pkicmn.ASMap) error {
	cfgs, err := g.loadConfigs(asMap)
	if err != nil {
		return err
	}
	keys, err := g.generateAllKeys(cfgs)
	if err != nil {
		return err
	}
	if err := g.createDirs(keys); err != nil {
		return err
	}
	if err := g.writeKeys(keys); err != nil {
		return err
	}
	return nil
}

func (g privGen) loadConfigs(asMap pkicmn.ASMap) (map[addr.IA]conf.Keys, error) {
	cfgs := make(map[addr.IA]conf.Keys)
	for _, ases := range asMap {
		for _, ia := range ases {
			file := conf.KeysFile(g.Dirs.Root, ia)
			keys, err := conf.LoadKeys(file)
			if err != nil {
				return nil, serrors.WrapStr("unable to load keys config file", err, "file", file)
			}
			cfgs[ia] = keys
		}
	}
	return cfgs, nil
}

func (g privGen) generateAllKeys(cfgs map[addr.IA]conf.Keys) (map[addr.IA][]keyconf.Key, error) {
	keys := make(map[addr.IA][]keyconf.Key)
	for ia, cfg := range cfgs {
		k, err := g.generateKeys(ia, cfg)
		if err != nil {
			return nil, serrors.WrapStr("unable to generate keys for AS", err, "ia", ia)
		}
		keys[ia] = k
	}
	return keys, nil
}

func (g privGen) generateKeys(ia addr.IA, cfg conf.Keys) ([]keyconf.Key, error) {
	var keys []keyconf.Key
	for keyType, metas := range cfg.Primary {
		for version, meta := range metas {
			usage, err := UsageFromTRCKeyType(keyType)
			if err != nil {
				return nil, serrors.WrapStr("error determining key usage", err,
					"type", keyType, "version", version)
			}
			key, err := g.generateKey(ia, version, usage, meta)
			if err != nil {
				return nil, serrors.WrapStr("error generating key", err, "type", keyType,
					"version", version)
			}
			keys = append(keys, key)
		}
	}
	for keyType, metas := range cfg.Issuer {
		for version, meta := range metas {
			usage, err := usageFromIssuerKeyType(keyType)
			if err != nil {
				return nil, serrors.WrapStr("error determining key usage", err,
					"type", keyType, "version", version)
			}
			key, err := g.generateKey(ia, version, usage, meta)
			if err != nil {
				return nil, serrors.WrapStr("error generating key", err, "type", keyType,
					"version", version)
			}
			keys = append(keys, key)
		}
	}
	for keyType, metas := range cfg.AS {
		for version, meta := range metas {
			usage, err := usageFromASKeyType(keyType)
			if err != nil {
				return nil, serrors.WrapStr("error determining key usage", err,
					"type", keyType, "version", version)
			}
			key, err := g.generateKey(ia, version, usage, meta)
			if err != nil {
				return nil, serrors.WrapStr("error generating key", err, "type", keyType,
					"version", version)
			}
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (g privGen) generateKey(ia addr.IA, version scrypto.KeyVersion,
	usage keyconf.Usage, meta conf.KeyMeta) (keyconf.Key, error) {

	raw, err := genKey(meta.Algorithm)
	if err != nil {
		return keyconf.Key{}, err
	}
	key := keyconf.Key{
		ID: keyconf.ID{
			Usage:   usage,
			IA:      ia,
			Version: version,
		},
		Type:      keyconf.PrivateKey,
		Algorithm: meta.Algorithm,
		Validity:  meta.Validity.Eval(time.Now()),
		Bytes:     raw,
	}
	return key, nil
}

func (g privGen) createDirs(keys map[addr.IA][]keyconf.Key) error {
	for ia := range keys {
		if err := os.MkdirAll(PrivateDir(g.Dirs.Out, ia), 0700); err != nil {
			return serrors.WrapStr("unable to make private keys directory", err, "ia", ia)
		}
	}
	return nil
}

func (g privGen) writeKeys(keys map[addr.IA][]keyconf.Key) error {
	for ia, list := range keys {
		for _, key := range list {
			b := key.PEM()
			file := filepath.Join(PrivateDir(g.Dirs.Out, ia), key.File())
			if err := pkicmn.WriteToFile(pem.EncodeToMemory(&b), file, 0600); err != nil {
				return serrors.WrapStr("error writing private key file", err, "file", file)
			}
		}
	}
	return nil
}

// UsageFromTRCKeyType converts the TRC key type to the appropriate usage.
func UsageFromTRCKeyType(keyType trc.KeyType) (keyconf.Usage, error) {
	switch keyType {
	case trc.IssuingGrantKey:
		return keyconf.TRCIssuingGrantKey, nil
	case trc.VotingOnlineKey:
		return keyconf.TRCVotingOnlineKey, nil
	case trc.VotingOfflineKey:
		return keyconf.TRCVotingOfflineKey, nil
	default:
		return "", serrors.New("unsupported key type", "type", keyType)
	}
}

func usageFromASKeyType(keyType cert.KeyType) (keyconf.Usage, error) {
	switch keyType {
	case cert.SigningKey:
		return keyconf.ASSigningKey, nil
	case cert.EncryptionKey:
		return keyconf.ASDecryptionKey, nil
	case cert.RevocationKey:
		return keyconf.ASRevocationKey, nil
	default:
		return "", serrors.New("unsupported key type", "type", keyType)
	}
}

func usageFromIssuerKeyType(keyType cert.KeyType) (keyconf.Usage, error) {
	switch keyType {
	case cert.IssuingKey:
		return keyconf.IssCertSigningKey, nil
	case cert.RevocationKey:
		return keyconf.IssRevocationKey, nil
	default:
		return "", serrors.New("unsupported key type", "type", keyType)
	}
}

func genKey(algo string) ([]byte, error) {
	switch algo {
	case scrypto.Ed25519:
		_, private, err := scrypto.GenKeyPair(algo)
		if err != nil {
			return nil, err
		}
		return ed25519.PrivateKey(private).Seed(), nil
	case scrypto.Curve25519xSalsa20Poly1305:
		_, private, err := scrypto.GenKeyPair(algo)
		return private, err
	default:
		return nil, serrors.New("unsupported key algorithm", "algo", algo)
	}
}
