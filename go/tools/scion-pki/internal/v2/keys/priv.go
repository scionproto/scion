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

package keys

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

func runPrivKey(asMap map[addr.ISD][]addr.IA, dirs pkicmn.Dirs) error {
	for _, ases := range asMap {
		for _, ia := range ases {
			if err := os.MkdirAll(PrivateDir(dirs.Out, ia), 0700); err != nil {
				return serrors.WrapStr("unable to make private keys directory", err, "ia", ia)
			}
			pkicmn.QuietPrint("Generating keys for %s\n", ia)
			if err := genAS(ia, dirs); err != nil {
				return serrors.WrapStr("unable to generate keys", err, "ia", ia)
			}
		}
	}
	return nil
}

func genAS(ia addr.IA, dirs pkicmn.Dirs) error {
	file := conf.KeysFile(dirs.Root, ia)
	keys, err := conf.LoadKeys(file)
	if err != nil {
		return serrors.WrapStr("unable to load keys config file", err, "file", file)
	}
	for keyType, metas := range keys.Primary {
		for version, meta := range metas {
			usage, err := usageFromTRCKeyType(keyType)
			if err != nil {
				return serrors.WrapStr("error determining key usage", err, "file", file,
					"type", keyType, "version", version)
			}
			if err := writePrivKeyFile(ia, version, usage, meta, dirs.Out); err != nil {
				return serrors.WrapStr("error generating key", err, "file", file,
					"type", keyType, "version", version)
			}
		}
	}
	for keyType, metas := range keys.Issuer {
		for version, meta := range metas {
			usage, err := usageFromIssuerKeyType(keyType)
			if err != nil {
				return serrors.WrapStr("error determining key usage", err, "file", file,
					"type", keyType, "version", version)
			}
			if err := writePrivKeyFile(ia, version, usage, meta, dirs.Out); err != nil {
				return serrors.WrapStr("error generating key", err, "file", file,
					"type", keyType, "version", version)
			}
		}
	}
	for keyType, metas := range keys.AS {
		for version, meta := range metas {
			usage, err := usageFromASKeyType(keyType)
			if err != nil {
				return serrors.WrapStr("error determining key usage", err, "file", file,
					"type", keyType, "version", version)
			}
			if err := writePrivKeyFile(ia, version, usage, meta, dirs.Out); err != nil {
				return serrors.WrapStr("error generating key", err, "file", file,
					"type", keyType, "version", version)
			}
		}
	}
	return nil
}

func writePrivKeyFile(ia addr.IA, version scrypto.KeyVersion, usage keyconf.Usage,
	meta conf.KeyMeta, outDir string) error {

	raw, err := genKey(meta.Algorithm)
	if err != nil {
		return err
	}
	key := keyconf.Key{
		Type:      keyconf.PrivateKey,
		Usage:     usage,
		Algorithm: meta.Algorithm,
		Validity:  meta.Validity.Eval(time.Now()),
		Version:   version,
		IA:        ia,
		Bytes:     raw,
	}
	b := key.PEM()
	file := filepath.Join(PrivateDir(outDir, ia), key.File())
	if err := pkicmn.WriteToFile(pem.EncodeToMemory(&b), file, 0600); err != nil {
		return serrors.WrapStr("error writing private key file", err, "file", file)
	}
	return nil
}

func usageFromTRCKeyType(keyType trc.KeyType) (keyconf.Usage, error) {
	switch keyType {
	case trc.IssuingKey:
		return keyconf.TRCIssuingKey, nil
	case trc.OnlineKey:
		return keyconf.TRCVotingOnlineKey, nil
	case trc.OfflineKey:
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
