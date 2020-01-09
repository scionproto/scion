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

package conf

import (
	"encoding"
	"io"
	"path/filepath"
	"strconv"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

// keysFileName is the file name of the key configuration.
const keysFileName = "keys.toml"

// KeysFile returns the file where the keys config is written to.
func KeysFile(dir string, ia addr.IA) string {
	return filepath.Join(pkicmn.GetAsPath(dir, ia), keysFileName)
}

// Keys holds the key configuration.
type Keys struct {
	Primary map[trc.KeyType]map[scrypto.KeyVersion]KeyMeta
	Issuer  map[cert.KeyType]map[scrypto.KeyVersion]KeyMeta
	AS      map[cert.KeyType]map[scrypto.KeyVersion]KeyMeta
}

// LoadKeys loads the keys from the provided file. The contents are already
// validated.
func LoadKeys(file string) (Keys, error) {
	var m tomlKeys
	if _, err := toml.DecodeFile(file, &m); err != nil {
		return Keys{}, serrors.WrapStr("unable to load key config from file", err, "file", file)
	}
	k, err := m.Keys()
	if err != nil {
		return Keys{}, serrors.WithCtx(err, "file", file)
	}
	if err := k.Validate(); err != nil {
		return Keys{}, serrors.WrapStr("unable to validate key config", err, "file", file)
	}
	return k, nil
}

// Encode writes the encoded keys config to the writer.
func (k Keys) Encode(w io.Writer) error {
	m, err := keyMarshalerFromKeys(k)
	if err != nil {
		return serrors.WrapStr("unable to convert key config", err)
	}
	if err := toml.NewEncoder(w).Encode(m); err != nil {
		return serrors.WrapStr("unable to encode key config", err)
	}
	return nil
}

// Validate checks all key metas.
func (k Keys) Validate() error {
	for t, metas := range k.Primary {
		if err := k.validateKeyMetas(metas); err != nil {
			return serrors.WithCtx(err, "type", t)
		}
	}
	for t, metas := range k.Issuer {
		if err := k.validateKeyMetas(metas); err != nil {
			return serrors.WithCtx(err, "type", t)
		}
	}
	for t, metas := range k.AS {
		if err := k.validateKeyMetas(metas); err != nil {
			return serrors.WithCtx(err, "type", t)
		}
	}
	return nil
}

func (k Keys) validateKeyMetas(metas map[scrypto.KeyVersion]KeyMeta) error {
	for ver, meta := range metas {
		if err := meta.Validate(); err != nil {
			return serrors.WrapStr("invalid key meta", err, "version", ver)
		}
	}
	return nil
}

// KeyMeta defines the key metadata.
type KeyMeta struct {
	Algorithm string   `toml:"algorithm"`
	Validity  Validity `toml:"validity"`
}

// Validate checks all values.
func (m KeyMeta) Validate() error {
	if m.Algorithm == "" {
		return serrors.New("algorithm not set")
	}
	if err := m.Validity.Validate(); err != nil {
		return serrors.WrapStr("invalid validity", err)
	}
	return nil
}

// tomlKeys is used for toml encoding and decoding because the library only
// allows string map keys.
type tomlKeys struct {
	Primary map[string]map[string]KeyMeta `toml:"primary"`
	Issuer  map[string]map[string]KeyMeta `toml:"issuer_cert"`
	AS      map[string]map[string]KeyMeta `toml:"as_cert"`
}

func (k tomlKeys) Keys() (Keys, error) {
	keys := Keys{
		Primary: make(map[trc.KeyType]map[scrypto.KeyVersion]KeyMeta),
		Issuer:  make(map[cert.KeyType]map[scrypto.KeyVersion]KeyMeta),
		AS:      make(map[cert.KeyType]map[scrypto.KeyVersion]KeyMeta),
	}
	for raw, metas := range k.Primary {
		var keyType trc.KeyType
		if err := keyType.UnmarshalText([]byte(raw)); err != nil {
			return Keys{}, serrors.WrapStr("unable to parse key type", err,
				"input", raw, "section", "primary")
		}
		parsed, err := k.convertKeyMetas(metas)
		if err != nil {
			return Keys{}, serrors.WithCtx(err, "key_type", raw)
		}
		keys.Primary[keyType] = parsed
	}
	if err := k.convertCertKeys(keys.Issuer, k.Issuer); err != nil {
		return Keys{}, serrors.WithCtx(err, "section", "issuer_cert")
	}
	if err := k.convertCertKeys(keys.AS, k.AS); err != nil {
		return Keys{}, serrors.WithCtx(err, "section", "as_cert")
	}
	return keys, nil
}

func (k tomlKeys) convertCertKeys(dst map[cert.KeyType]map[scrypto.KeyVersion]KeyMeta,
	src map[string]map[string]KeyMeta) error {

	for raw, metas := range src {
		var keyType cert.KeyType
		if err := keyType.UnmarshalText([]byte(raw)); err != nil {
			return serrors.WrapStr("unable to parse key type", err, "input", raw)
		}
		parsed, err := k.convertKeyMetas(metas)
		if err != nil {
			return serrors.WithCtx(err, "key_type", raw)
		}
		dst[keyType] = parsed
	}
	return nil
}

func (k tomlKeys) convertKeyMetas(
	metas map[string]KeyMeta) (map[scrypto.KeyVersion]KeyMeta, error) {

	m := make(map[scrypto.KeyVersion]KeyMeta, len(metas))
	for raw, meta := range metas {
		ver, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return nil, serrors.WrapStr("unable to parse key version", err, "input", raw)
		}
		m[scrypto.KeyVersion(ver)] = meta
	}
	return m, nil
}

func keyMarshalerFromKeys(k Keys) (tomlKeys, error) {
	m := tomlKeys{
		Primary: make(map[string]map[string]KeyMeta),
		Issuer:  make(map[string]map[string]KeyMeta),
		AS:      make(map[string]map[string]KeyMeta),
	}
	for keyType, metas := range k.Primary {
		if err := marshalKeyMetas(m.Primary, keyType, metas); err != nil {
			return tomlKeys{}, serrors.WithCtx(err, "section", "primary")
		}
	}
	for keyType, metas := range k.Issuer {
		if err := marshalKeyMetas(m.Issuer, keyType, metas); err != nil {
			return tomlKeys{}, serrors.WithCtx(err, "section", "issuer_cert")
		}
	}
	for keyType, metas := range k.AS {
		if err := marshalKeyMetas(m.AS, keyType, metas); err != nil {
			return tomlKeys{}, serrors.WithCtx(err, "section", "as_cert")
		}
	}
	return m, nil
}

func marshalKeyMetas(dst map[string]map[string]KeyMeta, keyType encoding.TextMarshaler,
	metas map[scrypto.KeyVersion]KeyMeta) error {

	raw, err := keyType.MarshalText()
	if err != nil {
		return serrors.WrapStr("unable to marshal key type", err, "key_type", keyType)
	}
	keyTypeStr := string(raw)
	for ver, meta := range metas {
		if _, ok := dst[keyTypeStr]; !ok {
			dst[keyTypeStr] = make(map[string]KeyMeta)
		}
		dst[keyTypeStr][strconv.FormatUint(uint64(ver), 10)] = meta
	}
	return nil
}
