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

package trcs

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var errReadFile = serrors.New("error reading file")

// Dir returns the directory where TRCs are written to.
func Dir(dir string, isd addr.ISD) string {
	return filepath.Join(pkicmn.GetIsdPath(dir, isd), pkicmn.TRCsDir)
}

// PartsDir returns the directory where the partially signed TRC is written to.
func PartsDir(dir string, isd addr.ISD, ver scrypto.Version) string {
	return filepath.Join(Dir(dir, isd), fmt.Sprintf(pkicmn.TRCPartsDirFmt, isd, ver))
}

// ProtoFile returns the file path for the prototype TRC.
func ProtoFile(dir string, isd addr.ISD, ver scrypto.Version) string {
	return filepath.Join(PartsDir(dir, isd, ver), fmt.Sprintf(pkicmn.TRCProtoNameFmt, isd, ver))
}

// SignedFile returns the file path for the signed TRC.
func SignedFile(dir string, isd addr.ISD, ver scrypto.Version) string {
	return filepath.Join(Dir(dir, isd), fmt.Sprintf(pkicmn.TrcNameFmt, isd, ver))
}

func loadTRC(file string) (*trc.TRC, trc.Encoded, error) {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	signed, err := trc.ParseSigned(raw)
	if err != nil {
		return nil, nil, err
	}
	t, err := signed.EncodedTRC.Decode()
	if err != nil {
		return nil, nil, err
	}
	return t, signed.EncodedTRC, nil
}

func loadKey(file string, ia addr.IA, usage keyconf.Usage,
	version scrypto.KeyVersion) (keyconf.Key, error) {

	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return keyconf.Key{}, serrors.Wrap(errReadFile, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return keyconf.Key{}, serrors.New("unable to parse PEM")
	}
	key, err := keyconf.KeyFromPEM(block)
	if err != nil {
		return keyconf.Key{}, serrors.WrapStr("unable to decode key", err)
	}
	if !key.IA.Equal(ia) {
		return keyconf.Key{}, serrors.New("IA does not match", "expected", ia, "actual", key.IA)
	}
	if key.Usage != usage {
		return keyconf.Key{}, serrors.New("usage does not match",
			"expected", usage, "actual", key.Usage)
	}
	if key.Version != version {
		return keyconf.Key{}, serrors.New("version does not match",
			"expected", version, "actual", key.Version)
	}
	return key, nil
}
