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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

type pubGen struct {
	Dirs pkicmn.Dirs
}

func (g pubGen) Run(asMap pkicmn.ASMap) error {
	privKeys, err := g.loadPrivateKeys(asMap)
	if err != nil {
		return err
	}
	pubKeys, err := g.generateKeys(privKeys)
	if err != nil {
		return err
	}
	if err := g.createDirs(pubKeys); err != nil {
		return err
	}
	if err := g.writeKeys(pubKeys); err != nil {
		return err
	}
	return nil
}

func (g pubGen) loadPrivateKeys(asMap pkicmn.ASMap) (map[addr.IA][]keyconf.Key, error) {
	priv := make(map[addr.IA][]keyconf.Key)
	for _, ases := range asMap {
		for _, ia := range ases {
			keys, err := g.loadASPrivateKeys(ia)
			if err != nil {
				return nil, serrors.WrapStr("unable to load private keys for AS", err, "ia", ia)
			}
			if len(keys) > 0 {
				priv[ia] = keys
			}
		}
	}
	return priv, nil
}

func (g pubGen) loadASPrivateKeys(ia addr.IA) ([]keyconf.Key, error) {
	matcher := fmt.Sprintf("%s/*.key", PrivateDir(g.Dirs.Out, ia))
	files, err := filepath.Glob(matcher)
	if err != nil {
		return nil, serrors.WrapStr("error searching for private key files", err)
	}
	var keys []keyconf.Key
	for _, file := range files {
		key, err := readPrivKey(file)
		if err != nil {
			return nil, serrors.WrapStr("error loading private key", err, "file", file)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (g pubGen) generateKeys(priv map[addr.IA][]keyconf.Key) (map[addr.IA][]keyconf.Key, error) {
	pubKeys := make(map[addr.IA][]keyconf.Key)
	for ia, privKeys := range priv {
		var keys []keyconf.Key
		for _, privKey := range privKeys {
			key, err := PublicKey(privKey)
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
		pubKeys[ia] = keys
	}
	return pubKeys, nil
}

func (g pubGen) createDirs(pubKeys map[addr.IA][]keyconf.Key) error {
	for ia := range pubKeys {
		if err := os.MkdirAll(PublicDir(g.Dirs.Out, ia), 0755); err != nil {
			return serrors.WrapStr("unable to make public keys directory", err, "ia", ia)
		}
	}
	return nil
}

func (g pubGen) writeKeys(pubKeys map[addr.IA][]keyconf.Key) error {
	for ia, list := range pubKeys {
		for _, key := range list {
			b := key.PEM()
			file := filepath.Join(PublicDir(g.Dirs.Out, ia), key.File())
			if err := pkicmn.WriteToFile(pem.EncodeToMemory(&b), file, 0644); err != nil {
				return serrors.WrapStr("error writing public key file", err, "file", file)
			}
		}
	}
	return nil
}

// LoadPublicKey attempts to load the private key and use that to generate the
// public key. If that fails, it attempts to load the public key directly. The
// boolean return value indicates whether the public key was derived from the
// private key.
func LoadPublicKey(dir string, id keyconf.ID) (keyconf.Key, bool, error) {
	priv, err := keyconf.LoadKeyFromFile(PrivateFile(dir, id), keyconf.PrivateKey, id)
	if err == nil {
		pub, err := PublicKey(priv)
		return pub, true, err
	}
	if !errors.Is(err, keyconf.ErrReadFile) {
		return keyconf.Key{}, false, err
	}
	pkicmn.QuietPrint("Unable to load private key for %s. Trying public key.\n", id.IA)
	file := PublicFile(dir, id)
	pub, err := keyconf.LoadKeyFromFile(file, keyconf.PublicKey, id)
	if err != nil {
		return keyconf.Key{}, false, serrors.WrapStr("unable to load public key", err, "file", file)
	}
	return pub, false, nil
}

// PublicKey translates a private to a public key.
func PublicKey(priv keyconf.Key) (keyconf.Key, error) {
	if priv.Type != keyconf.PrivateKey {
		return keyconf.Key{}, serrors.New("provided key is not a private key", "type", priv.Type)
	}
	raw, err := scrypto.GetPubKey(priv.Bytes, priv.Algorithm)
	if err != nil {
		return keyconf.Key{}, serrors.WrapStr("error generating public key", err)
	}
	key := keyconf.Key{
		ID: keyconf.ID{
			Usage:   priv.Usage,
			IA:      priv.IA,
			Version: priv.Version,
		},
		Type:      keyconf.PublicKey,
		Algorithm: priv.Algorithm,
		Validity:  priv.Validity,
		Bytes:     raw,
	}
	return key, nil
}

func readPrivKey(file string) (keyconf.Key, error) {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return keyconf.Key{}, serrors.WrapStr("unable to read file", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return keyconf.Key{}, serrors.WrapStr("unable to decode PEM", err)
	}
	key, err := keyconf.KeyFromPEM(block)
	if err != nil {
		return keyconf.Key{}, serrors.WrapStr("unable to decode private key", err)
	}
	if key.Type != keyconf.PrivateKey {
		return keyconf.Key{}, serrors.New("not a private key", "type", key.Type)
	}
	if _, name := filepath.Split(file); name != key.File() {
		return keyconf.Key{}, serrors.New("unexpected file name", "actual", name,
			"expected", key.File())
	}
	return key, nil
}
