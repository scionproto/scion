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
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/keys"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

// signedMeta keeps track of the TRC version.
type signedMeta struct {
	Signed  trc.Signed
	Version scrypto.Version
}

// pubKeys holds the public keys for a primary AS.
type pubKeys map[trc.KeyType]keyconf.Key

type protoGen struct {
	Dirs    pkicmn.Dirs
	Version scrypto.Version
}

// Run generates the prototype TRCs for all ISDs in the provided mapping. If no
// version is specified, the TRC configuration file with the highest version is
// chosen for each ISD. The generated TRCs are then written to disk.
func (g protoGen) Run(asMap pkicmn.ASMap) error {
	cfgs, err := loader{Dirs: g.Dirs, Version: g.Version}.LoadConfigs(asMap.ISDs())
	if err != nil {
		return serrors.WrapStr("unable to load TRC configs", err)
	}
	protos, err := g.Generate(cfgs)
	if err != nil {
		return serrors.WrapStr("unable to generate prototype TRCs", err)
	}
	if err := g.createDirs(protos); err != nil {
		return serrors.WrapStr("unable to create output directories", err)
	}
	if err := g.writeTRCs(protos); err != nil {
		return serrors.WrapStr("unable to write prototype TRCs", err)
	}
	return nil
}

// Generate generates the prototype TRCs for all provided configurations.
func (g protoGen) Generate(cfgs map[addr.ISD]conf.TRC) (map[addr.ISD]signedMeta, error) {
	trcs := make(map[addr.ISD]signedMeta)
	for isd, cfg := range cfgs {
		signed, err := g.generate(isd, cfg)
		if err != nil {
			return nil, serrors.WrapStr("unable to generate TRC", err,
				"isd", isd, "version", cfg.Version)
		}
		trcs[isd] = signed
	}
	return trcs, nil
}

// generate generates the prototype TRC for a specific configuration.
func (g protoGen) generate(isd addr.ISD, cfg conf.TRC) (signedMeta, error) {
	pubKeys, err := g.loadPubKeys(isd, cfg)
	if err != nil {
		return signedMeta{}, serrors.WrapStr("unable to load all public keys", err)
	}
	t, err := g.newTRC(isd, cfg, pubKeys)
	if err != nil {
		return signedMeta{}, serrors.WrapStr("unable to create prototype TRC", err)
	}
	enc, err := trc.Encode(t)
	if err != nil {
		return signedMeta{}, serrors.WrapStr("unable to encode TRC payload", err)
	}
	meta := signedMeta{
		Signed:  trc.Signed{EncodedTRC: enc},
		Version: t.Version,
	}
	return meta, nil
}

// loadPubKeys loads all public keys necessary for the given configuration.
func (g protoGen) loadPubKeys(isd addr.ISD, cfg conf.TRC) (map[addr.AS]pubKeys, error) {
	all := make(map[addr.AS]pubKeys)
	for as, primary := range cfg.PrimaryASes {
		ia := addr.IA{I: isd, A: as}
		keys := make(pubKeys)
		if err := g.insertIssuingKey(keys, ia, primary); err != nil {
			return nil, serrors.WithCtx(err, "as", as)
		}
		if err := g.insertVotingKeys(keys, ia, primary); err != nil {
			return nil, serrors.WithCtx(err, "as", as)
		}
		all[as] = keys
	}
	return all, nil
}

// insertIssuingKey inserts the issuing key if the primary is an issuing AS.
func (g protoGen) insertIssuingKey(dst pubKeys, ia addr.IA, primary conf.Primary) error {
	if !primary.Attributes.Contains(trc.Issuing) {
		return nil
	}
	desc := keyconf.ID{
		IA:      ia,
		Usage:   keyconf.TRCIssuingGrantKey,
		Version: *primary.IssuingGrantKeyVersion,
	}
	key, err := g.loadPubKey(desc)
	if err != nil {
		return serrors.WrapStr("unable to load issuing key", err)
	}
	dst[trc.IssuingGrantKey] = key
	return nil
}

// insertVotingKeys inserts the online and offline voting keys if the primary is
// a voting AS.
func (g protoGen) insertVotingKeys(dst pubKeys, ia addr.IA, primary conf.Primary) error {
	if !primary.Attributes.Contains(trc.Voting) {
		return nil
	}
	ids := map[trc.KeyType]keyconf.ID{
		trc.VotingOnlineKey: {
			IA:      ia,
			Usage:   keyconf.TRCVotingOnlineKey,
			Version: *primary.VotingOnlineKeyVersion,
		},
		trc.VotingOfflineKey: {
			IA:      ia,
			Usage:   keyconf.TRCVotingOfflineKey,
			Version: *primary.VotingOfflineKeyVersion,
		},
	}
	for keyType, id := range ids {
		key, err := g.loadPubKey(id)
		if err != nil {
			return serrors.WithCtx(err, "usage", id.Usage)
		}
		dst[keyType] = key
	}
	return nil
}

// loadPubKey attempts to load the private key and use it to generate the public
// key. If that fails, loadPubKey attempts to load the public key directly.
func (g protoGen) loadPubKey(id keyconf.ID) (keyconf.Key, error) {
	key, fromPriv, err := keys.LoadPublicKey(g.Dirs.Out, id)
	if err != nil {
		return keyconf.Key{}, err
	}
	if fromPriv {
		pkicmn.QuietPrint("Using private %s key for %s\n", id.Usage, id.IA)
		return key, nil
	}
	pkicmn.QuietPrint("Using public %s key for %s\n", id.Usage, id.IA)
	return key, nil
}

func (g protoGen) newTRC(isd addr.ISD, cfg conf.TRC, keys map[addr.AS]pubKeys) (*trc.TRC, error) {
	quorum := uint8(cfg.VotingQuorum)
	reset := *cfg.TrustResetAllowed
	val := cfg.Validity.Eval(time.Now())
	t := &trc.TRC{
		ISD:                  isd,
		Version:              cfg.Version,
		BaseVersion:          cfg.BaseVersion,
		Description:          cfg.Description,
		VotingQuorumPtr:      &quorum,
		FormatVersion:        1,
		GracePeriod:          &trc.Period{Duration: cfg.GracePeriod.Duration},
		TrustResetAllowedPtr: &reset,
		Validity:             &val,
		PrimaryASes:          make(trc.PrimaryASes),
		Votes:                make(map[addr.AS]trc.KeyType),
		ProofOfPossession:    make(map[addr.AS][]trc.KeyType),
	}
	for as, primary := range cfg.PrimaryASes {
		t.PrimaryASes[as] = trc.PrimaryAS{
			Attributes: sortAttributes(primary.Attributes),
			Keys:       getKeys(keys[as]),
		}
	}
	var prev *trc.TRC
	if !t.Base() {
		var err error
		file := SignedFile(g.Dirs.Out, isd, t.Version-1)
		if prev, _, err = loadTRC(file); err != nil {
			return nil, serrors.WrapStr("unable to load previous TRC", err, "file", file)
		}
	}
	if err := g.attachVotes(t, prev, cfg.Votes); err != nil {
		return nil, serrors.WrapStr("unable to attach votes", err)
	}
	if err := g.attachPOPs(t, prev); err != nil {
		return nil, serrors.WrapStr("unable to attach proof of possessions", err)
	}
	if err := t.ValidateInvariant(); err != nil {
		return nil, serrors.WrapStr("invariant violated", err)
	}
	if !t.Base() {
		if _, err := (&trc.UpdateValidator{Next: t, Prev: prev}).Validate(); err != nil {
			return nil, serrors.WrapStr("invalid update", err)
		}
	}
	return t, nil
}

func (g protoGen) attachVotes(next, prev *trc.TRC, voters []addr.AS) error {
	if next.Base() {
		return nil
	}
	info, err := (&trc.UpdateValidator{Next: next, Prev: prev}).UpdateInfo()
	if err != nil {
		return serrors.WrapStr("unable to get update info", err)
	}
	for _, voter := range voters {
		prevPrimary, ok := prev.PrimaryASes[voter]
		if !ok || !prevPrimary.Is(trc.Voting) {
			return serrors.New("non-voting AS cannot cast vote", "as", voter)
		}
		_, modifiedOnline := info.KeyChanges.Modified[trc.VotingOnlineKey][voter]
		if info.Type != trc.RegularUpdate || modifiedOnline {
			next.Votes[voter] = trc.VotingOfflineKey
		} else {
			next.Votes[voter] = trc.VotingOnlineKey
		}
	}
	return nil
}

func (g protoGen) attachPOPs(next, prev *trc.TRC) error {
	if next.Base() {
		for as, primary := range next.PrimaryASes {
			keyTypes := make([]trc.KeyType, 0, len(primary.Keys))
			for keyType := range primary.Keys {
				keyTypes = append(keyTypes, keyType)
			}
			sort.Slice(keyTypes, func(i, j int) bool { return keyTypes[i] < keyTypes[j] })
			next.ProofOfPossession[as] = keyTypes
		}
		return nil
	}
	info, err := (&trc.UpdateValidator{Next: next, Prev: prev}).UpdateInfo()
	if err != nil {
		return serrors.WrapStr("unable to get update info", err)
	}
	for keyType, metas := range info.KeyChanges.Fresh {
		for as := range metas {
			next.ProofOfPossession[as] = append(next.ProofOfPossession[as], keyType)
		}
	}
	for keyType, metas := range info.KeyChanges.Modified {
		for as := range metas {
			next.ProofOfPossession[as] = append(next.ProofOfPossession[as], keyType)
		}
	}
	for _, keyTypes := range next.ProofOfPossession {
		sort.Slice(keyTypes, func(i, j int) bool { return keyTypes[i] < keyTypes[j] })
	}
	return nil
}

func (g protoGen) createDirs(trcs map[addr.ISD]signedMeta) error {
	for isd, meta := range trcs {
		dir := filepath.Dir(ProtoFile(g.Dirs.Out, isd, meta.Version))
		if err := os.MkdirAll(dir, 0755); err != nil {
			return serrors.WrapStr("unable to make TRC parts directory", err, "dir", dir)
		}
	}
	return nil
}

func (g protoGen) writeTRCs(trcs map[addr.ISD]signedMeta) error {
	for isd, meta := range trcs {
		raw, err := trc.EncodeSigned(meta.Signed)
		if err != nil {
			return serrors.WrapStr("unable to marshal prototype TRC", err, "isd", isd)
		}
		file := ProtoFile(g.Dirs.Out, isd, meta.Version)
		if err := pkicmn.WriteToFile(raw, file, 0644); err != nil {
			return serrors.WrapStr("unable to write prototype TRC", err, "file", file)
		}
	}
	return nil
}

func sortAttributes(attrs []trc.Attribute) []trc.Attribute {
	a := append([]trc.Attribute{}, attrs...)
	sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
	return a
}

func getKeys(keys map[trc.KeyType]keyconf.Key) map[trc.KeyType]scrypto.KeyMeta {
	m := make(map[trc.KeyType]scrypto.KeyMeta)
	for keyType, key := range keys {
		m[keyType] = scrypto.KeyMeta{
			Algorithm:  key.Algorithm,
			Key:        append([]byte{}, key.Bytes...),
			KeyVersion: key.Version,
		}
	}
	return m
}
