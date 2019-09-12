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
	"bytes"
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

func runCombine(selector string) error {
	asMap, err := pkicmn.ProcessSelector(selector)
	if err != nil {
		return err
	}
	for isd := range asMap {
		if err = combineAndWrite(isd); err != nil {
			return common.NewBasicError("unable to combine TRC", err, "isd", isd)
		}
	}
	return nil
}

func combineAndWrite(isd addr.ISD) error {
	isdCfg, err := conf.LoadISDCfg(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
	if err != nil {
		return common.NewBasicError("error loading ISD config", err)
	}
	t, encoded, err := loadProtoTRC(isd, isdCfg.Version)
	if err != nil {
		return common.NewBasicError("unable to load prototype TRC", err)
	}
	signatures, err := loadUniqueSignatures(isd, t.Version, encoded)
	if err != nil {
		return common.NewBasicError("unable to load signatures", err)
	}
	signed := &trc.Signed{
		EncodedTRC: encoded,
		Signatures: signatures,
	}
	if err := validateAndWrite(t, signed); err != nil {
		return err
	}
	return nil
}

func loadUniqueSignatures(isd addr.ISD, ver scrypto.Version,
	encoded trc.Encoded) ([]trc.Signature, error) {

	fnames, err := filepath.Glob(PartsFile(isd, uint64(ver), "*"))
	if err != nil {
		return nil, common.NewBasicError("unable to list all signatures", err)
	}
	signatures := make(map[trc.Protected]trc.Signature)
	for _, fname := range fnames {
		raw, err := ioutil.ReadFile(fname)
		if err != nil {
			return nil, common.NewBasicError("unable to read file", err, "file", fname)
		}
		var signed trc.Signed
		if err := json.Unmarshal(raw, &signed); err != nil {
			return nil, common.NewBasicError("unable to parse file", err, "file", fname)
		}
		if !bytes.Equal(encoded, signed.EncodedTRC) {
			pkicmn.QuietPrint("Ignoring signed in %s. Payload is different", fname)
		}
		for _, sign := range signed.Signatures {
			protected, err := sign.EncodedProtected.Decode()
			if err != nil {
				return nil, common.NewBasicError("unable to parse protected", err, "file", fname)
			}
			signatures[protected] = sign
		}
	}
	return sortSignatures(signatures), nil
}
