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
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sort"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

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

// PartsFile returns the file path for the partially signed TRC for a given AS.
func PartsFile(dir string, ia addr.IA, ver scrypto.Version) string {
	return filepath.Join(PartsDir(dir, ia.I, ver),
		fmt.Sprintf(pkicmn.TRCSigPartFmt, ia.I, ver, ia.FileFmt(false)))
}

// AllPartsFiles returns a glob string that matches all TRC parts for the given ISD and version.
func AllPartsFiles(dir string, isd addr.ISD, ver scrypto.Version) string {
	return filepath.Join(PartsDir(dir, isd, ver), fmt.Sprintf(pkicmn.TRCSigPartFmt, isd, ver, "*"))
}

// SignedFile returns the file path for the signed TRC.
func SignedFile(dir string, isd addr.ISD, ver scrypto.Version) string {
	return filepath.Join(Dir(dir, isd), fmt.Sprintf(pkicmn.TrcNameFmt, isd, ver))
}

func sortSignatures(signatures map[trc.Protected]trc.Signature) []trc.Signature {
	keys := make([]trc.Protected, 0, len(signatures))
	for key := range signatures {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		switch {
		case keys[i].AS != keys[j].AS:
			return keys[i].AS < keys[j].AS
		case keys[i].Type != keys[j].Type:
			return keys[i].Type < keys[j].Type
		case keys[i].KeyType != keys[j].KeyType:
			return keys[i].KeyType < keys[j].KeyType
		}
		return false
	})
	sigs := make([]trc.Signature, 0, len(keys))
	for _, key := range keys {
		sigs = append(sigs, signatures[key])
	}
	return sigs
}

func loadTRC(file string) (*trc.TRC, trc.Encoded, error) {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	signed, err := trc.ParseSigned(raw)
	if err != nil {
		return nil, "", err
	}
	t, err := signed.EncodedTRC.Decode()
	if err != nil {
		return nil, "", err
	}
	return t, signed.EncodedTRC, nil
}
