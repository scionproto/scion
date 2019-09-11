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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

// Dir returns the directory where TRCs are written to.
func Dir(isd addr.ISD) string {
	return filepath.Join(pkicmn.GetIsdPath(pkicmn.OutDir, isd), pkicmn.TRCsDir)
}

// PartsDir returns the directory where the partially signed TRC is written to.
func PartsDir(isd addr.ISD, ver uint64) string {
	return filepath.Join(Dir(isd), fmt.Sprintf(pkicmn.TRCPartsDirFmt, isd, ver))
}

// ProtoFile returns the file path for the prototype TRC.
func ProtoFile(isd addr.ISD, ver uint64) string {
	return filepath.Join(PartsDir(isd, ver), fmt.Sprintf(pkicmn.TRCProtoNameFmt, isd, ver))
}

// PartsFile returns the file path for the partially signed TRC with the selector.
func PartsFile(isd addr.ISD, ver uint64, selector string) string {
	return filepath.Join(PartsDir(isd, ver),
		fmt.Sprintf(pkicmn.TRCSigPartFmt, isd, ver, selector))
}

// SignedFile returns the file path for the signed TRC.
func SignedFile(isd addr.ISD, ver uint64) string {
	return filepath.Join(Dir(isd), fmt.Sprintf(pkicmn.TrcNameFmt, isd, ver))
}

func validateAndWrite(t *trc.TRC, signed *trc.Signed) error {
	raw, err := json.Marshal(signed)
	if err != nil {
		return common.NewBasicError("unable to marshal signed TRC", err)
	}
	if err := validateResult(raw); err != nil {
		return common.NewBasicError("unable to validate signed TRC", err)
	}
	if err := os.MkdirAll(Dir(t.ISD), 0755); err != nil {
		return common.NewBasicError("unable to create TRC dir", err)
	}
	return pkicmn.WriteToFile(raw, SignedFile(t.ISD, uint64(t.Version)), 0644)
}

func validateResult(raw []byte) error {
	var signed trc.Signed
	if err := json.Unmarshal(raw, &signed); err != nil {
		return common.NewBasicError("invalid signed TRC", err)
	}
	t, err := signed.EncodedTRC.Decode()
	if err != nil {
		return common.NewBasicError("invalid TRC payload", err)
	}
	if err := t.ValidateInvariant(); err != nil {
		return common.NewBasicError("violated TRC invariant", err)
	}
	// FIXME(roosd): Should also verify votes when supported.
	v := trc.POPVerifier{
		TRC:        t,
		Encoded:    signed.EncodedTRC,
		Signatures: signed.Signatures,
	}
	if err := v.Verify(); err != nil {
		return common.NewBasicError("proof of possesions fail to verify", err)
	}
	return nil
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
