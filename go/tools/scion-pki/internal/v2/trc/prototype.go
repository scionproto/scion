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
	"os"
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

func runProto(args []string) {
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		pkicmn.ErrorAndExit("Error: %s\n", err)
	}
	for isd := range asMap {
		if err = genAndWriteProto(isd); err != nil {
			pkicmn.ErrorAndExit("Error generating proto TRC for ISD %d: %s\n", isd, err)
		}
	}
	os.Exit(0)
}

func genAndWriteProto(isd addr.ISD) error {
	isdCfg, err := conf.LoadISDCfg(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
	if err != nil {
		return common.NewBasicError("error loading ISD config", err)
	}
	t, encoded, err := genProto(isd, isdCfg)
	if err != nil {
		return common.NewBasicError("unable to generate TRC", err)
	}
	signed := &trc.Signed{EncodedTRC: encoded}
	raw, err := json.Marshal(signed)
	if err != nil {
		return common.NewBasicError("unable to marshal", err)
	}
	if err := os.MkdirAll(PartsDir(isd, uint64(t.Version)), 0755); err != nil {
		return err
	}
	return pkicmn.WriteToFile(raw, ProtoFile(isd, uint64(t.Version)), 0644)
}

func genProto(isd addr.ISD, isdCfg *conf.ISDCfg) (*trc.TRC, trc.Encoded, error) {
	pkicmn.QuietPrint("Generating proto TRC for ISD %d\n", isd)
	primaryASes, err := loadPrimaryASes(isd, isdCfg, nil)
	if err != nil {
		return nil, nil, common.NewBasicError("error loading primary ASes configs", err)
	}
	t, err := newTRC(isd, isdCfg, primaryASes)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := trc.Encode(t)
	if err != nil {
		return nil, nil, common.NewBasicError("unable to encode TRC", err)
	}
	return t, encoded, nil
}

func newTRC(isd addr.ISD, isdCfg *conf.ISDCfg, primaryASes map[addr.AS]*asCfg) (*trc.TRC, error) {
	quorum := uint8(isdCfg.TRC.VotingQuorum)
	reset := isdCfg.TRC.TrustResetAllowed
	t := &trc.TRC{
		ISD:                  isd,
		Version:              scrypto.Version(isdCfg.TRC.Version),
		BaseVersion:          scrypto.Version(isdCfg.TRC.BaseVersion),
		Description:          isdCfg.Desc,
		VotingQuorumPtr:      &quorum,
		FormatVersion:        1,
		GracePeriod:          &trc.Period{Duration: isdCfg.TRC.GracePeriod},
		TrustResetAllowedPtr: &reset,
		Validity:             createValidity(isdCfg.TRC.NotBefore, isdCfg.TRC.Validity),
		PrimaryASes:          make(trc.PrimaryASes),
		Votes:                make(map[addr.AS]trc.Vote),
		ProofOfPossession:    make(map[addr.AS][]trc.KeyType),
	}
	if !t.Base() {
		return nil, common.NewBasicError("TRC updates not supported yet", nil,
			"version", t.Version, "base", t.BaseVersion)
	}
	for as, cfg := range primaryASes {
		t.PrimaryASes[as] = trc.PrimaryAS{
			Attributes: getAttributes(isdCfg, as),
			Keys:       getKeys(cfg),
		}
		t.ProofOfPossession[as] = getKeyTypes(cfg)
	}
	if err := t.ValidateInvariant(); err != nil {
		return nil, common.NewBasicError("invariant violated", err)
	}
	return t, nil
}

func createValidity(notBefore uint32, validity time.Duration) *scrypto.Validity {
	val := &scrypto.Validity{
		NotBefore: util.UnixTime{Time: util.SecsToTime(notBefore)},
	}
	if notBefore == 0 {
		val.NotBefore.Time = time.Now()
	}
	val.NotAfter = util.UnixTime{Time: val.NotBefore.Add(validity)}
	return val
}

func getAttributes(isdCfg *conf.ISDCfg, as addr.AS) []trc.Attribute {
	var a []trc.Attribute
	m := map[trc.Attribute][]addr.AS{
		trc.Authoritative: isdCfg.AuthoritativeASes,
		trc.Core:          isdCfg.CoreASes,
		trc.Issuing:       isdCfg.IssuingASes,
		trc.Voting:        isdCfg.VotingASes,
	}
	for attr, list := range m {
		if pkicmn.ContainsAS(list, as) {
			a = append(a, attr)
		}
	}
	sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
	return a
}

func getKeys(cfg *asCfg) map[trc.KeyType]scrypto.KeyMeta {
	// FIXME(roosd): allow for different key versions.
	m := make(map[trc.KeyType]scrypto.KeyMeta)
	for keyType, key := range cfg.Keys {
		algo := cfg.KeyTypeToAlgo(keyType)
		pubKey, err := scrypto.GetPubKey(key, algo)
		if err != nil {
			pkicmn.ErrorAndExit("unsupported algorithm passed validation algo=%s", algo)
		}
		m[keyType] = scrypto.KeyMeta{
			Algorithm:  algo,
			Key:        pubKey,
			KeyVersion: 1,
		}
	}
	return m
}

func getKeyTypes(cfg *asCfg) []trc.KeyType {
	keyTypes := make([]trc.KeyType, 0, len(cfg.Keys))
	for keyType := range cfg.Keys {
		keyTypes = append(keyTypes, keyType)
	}
	sort.Slice(keyTypes, func(i, j int) bool { return keyTypes[i] < keyTypes[j] })
	return keyTypes
}
