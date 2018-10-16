// Copyright 2018 ETH Zurich, Anapaya Systems
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

package keyconf

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

type Conf struct {
	// IssSigKey is the AS issuer signing Key.
	IssSigKey common.RawBytes
	// DecryptKey is the AS decryption key.
	DecryptKey common.RawBytes
	// OffRootKey is the AS offline root key.
	OffRootKey common.RawBytes
	// OnRootKey is the AS online root key.
	OnRootKey common.RawBytes
	// SignKey is the AS signing key.
	SignKey common.RawBytes
	// Master contains the AS master keys.
	Master Master
}

const (
	IssSigKeyFile = "core-sig.seed" // TODO(roosd): rename "core-sig.key" -> "iss-sig.key"
	DecKeyFile    = "as-decrypt.key"
	OffKeyFile    = "offline-root.seed"
	OnKeyFile     = "online-root.seed"
	SigKeyFile    = "as-sig.seed"
	MasterKey0    = "master0.key"
	MasterKey1    = "master1.key"

	RawKey = "raw"

	ErrorOpen    = "Unable to load key"
	ErrorParse   = "Unable to parse key file"
	ErrorUnknown = "Unknown algorithm"
)

// Load loads key configuration from specified path.
// issSigKey, onKey, offKey, master can be set true, to load the respective keys.
func Load(path string, issSigKey, onKey, offKey, master bool) (*Conf, error) {
	conf := &Conf{}
	var err error
	conf.DecryptKey, err = loadKeyCond(filepath.Join(path, DecKeyFile),
		scrypto.Curve25519xSalsa20Poly1305, true)
	if err != nil {
		return nil, err
	}
	conf.SignKey, err = loadKeyCond(filepath.Join(path, SigKeyFile), scrypto.Ed25519, true)
	if err != nil {
		return nil, err
	}
	conf.IssSigKey, err = loadKeyCond(filepath.Join(path, IssSigKeyFile),
		scrypto.Ed25519, issSigKey)
	if err != nil {
		return nil, err
	}
	conf.OffRootKey, err = loadKeyCond(filepath.Join(path, OffKeyFile), scrypto.Ed25519, offKey)
	if err != nil {
		return nil, err
	}
	conf.OnRootKey, err = loadKeyCond(filepath.Join(path, OnKeyFile), scrypto.Ed25519, onKey)
	if err != nil {
		return nil, err
	}
	if conf.Master, err = loadMasterCond(path, master); err != nil {
		return nil, err
	}
	return conf, nil
}

func loadKeyCond(file string, algo string, load bool) (common.RawBytes, error) {
	if !load {
		return nil, nil
	}
	return LoadKey(file, algo)
}

func loadMasterCond(path string, load bool) (Master, error) {
	if !load {
		return Master{}, nil
	}
	return LoadMaster(path)
}

// LoadKey decodes a base64 encoded key stored in file and returns the raw bytes.
func LoadKey(file string, algo string) (common.RawBytes, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, common.NewBasicError(ErrorOpen, err)
	}
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(dbuf, b)
	if err != nil {
		return nil, common.NewBasicError(ErrorParse, err)
	}
	dbuf = dbuf[:n]
	switch strings.ToLower(algo) {
	case RawKey, scrypto.Curve25519xSalsa20Poly1305:
		return dbuf, nil
	case scrypto.Ed25519:
		return common.RawBytes(ed25519.NewKeyFromSeed(dbuf)), nil
	default:
		return nil, common.NewBasicError(ErrorUnknown, nil, "algo", algo)
	}
}

func (c *Conf) String() string {
	return fmt.Sprintf("DecryptKey:%s SigningKey:%s IssSigningKey: %s "+
		"OfflineRootKey:%s OnlineRootKey:%s Master:%s",
		//XXX(shitz): Uncomment for debugging.
		//c.DecryptKey, c.SignKey, c.IssSigKey, c.OffRootKey, c.OnRootKey, c.Master)
		"<redacted>", "<redacted>", "<redacted>", "<redacted>", "<redacted>", "<redacted>")
}

type Master struct {
	Key0 common.RawBytes
	Key1 common.RawBytes
}

func LoadMaster(path string) (Master, error) {
	var err error
	m := Master{}
	if m.Key0, err = LoadKey(filepath.Join(path, MasterKey0), RawKey); err != nil {
		return m, err
	}
	if m.Key1, err = LoadKey(filepath.Join(path, MasterKey1), RawKey); err != nil {
		return m, err
	}
	return m, nil
}

func (m *Master) String() string {
	return fmt.Sprintf("Key0:%s Key1:%s",
		//XXX(roosd): Uncomment for debugging.
		//m.Key0, m.Key1
		"<redacted>", "<redacted>")
}
