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

const (
	MasterKey0 = "master0.key"
	MasterKey1 = "master1.key"

	// FIXME(roosd): removed unused keys above.

	ASSigKeyFile = "as-signing.key"
	ASDecKeyFile = "as-decrypt.key"
	ASRevKeyFile = "as-revocation.key"

	IssuerRevKeyFile  = "issuer-revocation.key"
	IssuerCertKeyFile = "issuer-cert-signing.key"

	TRCOnlineKeyFile  = "trc-online.key"
	TRCOfflineKeyFile = "trc-offline.key"
	TRCIssuingKeyFile = "trc-issuing.key"

	RawKey = "raw"
)

// Errors
const (
	ErrOpen    common.ErrMsg = "Unable to load key"
	ErrParse   common.ErrMsg = "Unable to parse key file"
	ErrUnknown common.ErrMsg = "Unknown algorithm"
)

// LoadKey decodes a base64 encoded key stored in file and returns the raw bytes.
func loadKey(file string, algo string) (common.RawBytes, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, common.NewBasicError(ErrOpen, err)
	}
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(dbuf, b)
	if err != nil {
		return nil, common.NewBasicError(ErrParse, err)
	}
	dbuf = dbuf[:n]
	switch strings.ToLower(algo) {
	case RawKey, scrypto.Curve25519xSalsa20Poly1305:
		return dbuf, nil
	case scrypto.Ed25519:
		return common.RawBytes(ed25519.NewKeyFromSeed(dbuf)), nil
	default:
		return nil, common.NewBasicError(ErrUnknown, nil, "algo", algo)
	}
}

type Master struct {
	Key0 []byte
	Key1 []byte
}

func LoadMaster(path string) (Master, error) {
	var err error
	m := Master{}
	if m.Key0, err = loadKey(filepath.Join(path, MasterKey0), RawKey); err != nil {
		return m, err
	}
	if m.Key1, err = loadKey(filepath.Join(path, MasterKey1), RawKey); err != nil {
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
