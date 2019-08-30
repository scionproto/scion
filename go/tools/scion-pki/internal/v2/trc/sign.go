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

package trc

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

func runSign(args []string) {
	_, selector, err := pkicmn.ParseSelector(args[0])
	if err != nil {
		pkicmn.ErrorAndExit("error: %s\n", err)
	}
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		pkicmn.ErrorAndExit("error: %s\n", err)
	}
	for isd, ases := range asMap {
		if err = genAndWriteSignatures(isd, ases, selector); err != nil {
			pkicmn.ErrorAndExit("error signing TRC for ISD %d: %s\n", isd, err)
		}
	}
	os.Exit(0)
}

func genAndWriteSignatures(isd addr.ISD, ases []addr.IA, selector string) error {
	isdCfg, err := conf.LoadISDCfg(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
	if err != nil {
		return common.NewBasicError("error loading ISD config", err)
	}
	primaryASes, err := loadPrimaryASes(isd, isdCfg, ases)
	if err != nil {
		return common.NewBasicError("error loading AS configs", err)
	}
	t, encoded, err := loadProtoTRC(isd, isdCfg.Version)
	if err != nil {
		return common.NewBasicError("unable to load prototype TRC", err)
	}
	if err := sanityChecks(isd, isdCfg, t); err != nil {
		return common.NewBasicError("invalid prototype TRC", err)
	}
	signed, err := signTRC(t, encoded, primaryASes)
	if err != nil {
		return common.NewBasicError("unable to partially sign TRC", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return common.NewBasicError("error json-encoding partially signed TRC", err)
	}
	if err := os.MkdirAll(PartsDir(isd, uint64(t.Version)), 0755); err != nil {
		return err
	}
	return pkicmn.WriteToFile(raw, PartsFile(isd, uint64(t.Version), selector), 0644)
}

func loadProtoTRC(isd addr.ISD, ver uint64) (*trc.TRC, trc.Encoded, error) {
	raw, err := ioutil.ReadFile(ProtoFile(isd, ver))
	if err != nil {
		return nil, nil, err
	}
	var signed trc.Signed
	if err := json.Unmarshal(raw, &signed); err != nil {
		return nil, nil, err
	}
	t, err := signed.EncodedTRC.Decode()
	if err != nil {
		return nil, nil, err
	}
	return t, signed.EncodedTRC, nil
}

// sanityChecks does some small sanity checks to ensure the right TRC is signed.
func sanityChecks(isd addr.ISD, isdCfg *conf.ISDCfg, t *trc.TRC) error {
	if isd != t.ISD {
		return common.NewBasicError("ISD does not match", nil, "proto", t.ISD, "cfg", isd)
	}
	if isdCfg.Version != uint64(t.Version) {
		return common.NewBasicError("version does not match", nil, "proto", t.Version,
			"cfg", isdCfg.Version)
	}
	if isdCfg.BaseVersion != uint64(t.BaseVersion) {
		return common.NewBasicError("base_version does not match", nil, "proto", t.BaseVersion,
			"cfg", isdCfg.BaseVersion)
	}
	return nil
}

func signTRC(t *trc.TRC, encoded trc.Encoded, primaryASes map[addr.AS]*asCfg) (
	*trc.Signed, error) {

	signatures := make(map[trc.Protected]trc.Signature)
	// FIXME(roosd): Here votes should be cast in updates.
	for as, keyTypes := range t.ProofOfPossession {
		// Skip ASes that are not selected.
		if _, ok := primaryASes[as]; !ok {
			continue
		}
		for _, keyType := range keyTypes {
			protected := trc.Protected{
				AS:         as,
				Algorithm:  t.PrimaryASes[as].Keys[keyType].Algorithm,
				KeyType:    keyType,
				KeyVersion: t.PrimaryASes[as].Keys[keyType].KeyVersion,
				Type:       trc.POPSignature,
			}
			encProtected, err := trc.EncodeProtected(protected)
			if err != nil {
				return nil, err
			}
			signature, err := scrypto.Sign(trc.SigInput(encProtected, encoded),
				primaryASes[as].Keys[keyType], primaryASes[as].KeyTypeToAlgo(keyType))
			if err != nil {
				return nil, err
			}
			signatures[protected] = trc.Signature{
				EncodedProtected: encProtected,
				Signature:        signature,
			}
		}
	}
	if len(signatures) == 0 {
		return nil, common.NewBasicError("no signature generated", nil)
	}
	signed := &trc.Signed{
		EncodedTRC: encoded,
		Signatures: sortSignatures(signatures),
	}
	return signed, nil
}
