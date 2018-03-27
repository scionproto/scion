// Copyright 2018 ETH Zurich
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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/common"
)

type KeyConf struct {
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
}

const (
	IssSigKeyFile = "core-sig.key" // TODO(roosd): rename "core-sig.key" -> "iss-sig.key"
	DecKeyFile    = "as-decrypt.key"
	OffKeyFile    = "offline-root.key"
	OnKeyFile     = "online-root.key"
	SigKeyFile    = "as-sig.key"
)

const (
	ErrorOpen  = "Unable to load key"
	ErrorParse = "Unable to parse key"
)

// LoadKeyConf loads key configuration from specified path.
// issSigKey, onKey, offKey can be set true, to load the respective keys.
func LoadKeyConf(path string, issSigKey, onKey, offKey bool) (*KeyConf, error) {
	conf := &KeyConf{}
	var err error
	if conf.DecryptKey, err = loadKeyCond(filepath.Join(path, DecKeyFile), true); err != nil {
		return nil, err
	}
	if conf.SignKey, err = loadKeyCond(filepath.Join(path, SigKeyFile), true); err != nil {
		return nil, err
	}
	if conf.IssSigKey, err = loadKeyCond(filepath.Join(path, IssSigKeyFile), issSigKey); err != nil {

	}
	if conf.OffRootKey, err = loadKeyCond(filepath.Join(path, OffKeyFile), offKey); err != nil {
		return nil, err
	}
	if conf.OnRootKey, err = loadKeyCond(filepath.Join(path, OnKeyFile), onKey); err != nil {
		return nil, err
	}
	return conf, nil
}

func loadKeyCond(file string, load bool) (common.RawBytes, error) {
	if !load {
		return nil, nil
	}
	return LoadKey(file)
}

// LoadKey decodes a base64 encoded key stored in file and returns the raw bytes.
func LoadKey(file string) (common.RawBytes, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, common.NewBasicError(ErrorOpen, err)
	}
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(dbuf, b)
	if err != nil {
		return nil, common.NewBasicError(ErrorParse, err)
	}
	return dbuf[:n], nil
}

func (a *KeyConf) String() string {
	return fmt.Sprintf(
		"DecryptKey:%s SigningKey:%s IssSigningKey: %s OfflineRootKey:%s OnlineRootKey:%s",
		a.DecryptKey, a.SignKey, a.IssSigKey, a.OffRootKey, a.OnRootKey)
}
