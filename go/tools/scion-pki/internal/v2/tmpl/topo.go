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

package tmpl

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

var (
	notBefore   uint32
	rawValidity string
)

type topoGen struct {
	Dirs     pkicmn.Dirs
	Validity conf.Validity
}

func (g topoGen) Run(topo topoFile) error {
	if err := g.setupDirs(topo); err != nil {
		return serrors.WrapStr("unable to setup dirs", err)
	}
	trcs, err := g.genTRCs(topo)
	if err != nil {
		return serrors.WrapStr("unable to generate TRC configs", err)
	}
	if err := g.genKeys(topo, trcs); err != nil {
		return serrors.WrapStr("unable to generate key configs", err)
	}
	if err := g.genCerts(topo, trcs); err != nil {
		return serrors.WrapStr("unable to generate certificate configs", err)
	}
	pkicmn.QuietPrint("Generated all configuration files\n")
	return nil
}

func (g topoGen) setupDirs(topo topoFile) error {
	for isd := range topo.ISDs() {
		dir := filepath.Dir(conf.TRCFile(g.Dirs.Root, isd, 1))
		if err := os.MkdirAll(dir, 0755); err != nil {
			return serrors.WrapStr("unable to make ISD directory", err, "isd", isd, "dir", dir)
		}
	}
	for ia := range topo.ASes {
		if err := os.MkdirAll(filepath.Dir(conf.KeysFile(g.Dirs.Root, ia)), 0755); err != nil {
			return serrors.WrapStr("unable to make AS directory", err, "ia", ia)
		}
	}
	return nil
}

func (g topoGen) genTRCs(topo topoFile) (map[addr.ISD]conf.TRC2, error) {
	trcs := make(map[addr.ISD]conf.TRC2)
	for isd := range topo.ISDs() {
		trcs[isd] = g.genTRC(isd, topo)
		var buf bytes.Buffer
		if err := trcs[isd].Encode(&buf); err != nil {
			return nil, serrors.WithCtx(err, "isd", isd)
		}
		file := conf.TRCFile(g.Dirs.Root, isd, trcs[isd].Version)
		if err := pkicmn.WriteToFile(buf.Bytes(), file, 0644); err != nil {
			return nil, serrors.WrapStr("unable to write TRC config", err, "isd", isd, "file", file)
		}
	}
	return trcs, nil
}

func (g topoGen) genTRC(isd addr.ISD, topo topoFile) conf.TRC2 {
	cores := topo.Cores(isd)
	reset := true
	cfg := conf.TRC2{
		Description: fmt.Sprintf("ISD %d", isd),
		Version:     1,
		BaseVersion: 1,
		// XXX(roosd): Choose quorum according to your security needs.
		// This simply serves an example.
		VotingQuorum:      uint16(len(cores)/2 + 1),
		TrustResetAllowed: &reset,
		Votes:             []addr.AS{},
		Validity:          g.Validity,
		PrimaryASes:       make(map[addr.AS]conf.Primary),
	}
	for _, as := range cores {
		iss, on, off := scrypto.KeyVersion(1), scrypto.KeyVersion(1), scrypto.KeyVersion(1)
		cfg.PrimaryASes[as] = conf.Primary{
			Attributes: []trc.Attribute{trc.Authoritative, trc.Core, trc.Issuing,
				trc.Voting},
			IssuingKeyVersion:       &iss,
			VotingOfflineKeyVersion: &off,
			VotingOnlineKeyVersion:  &on,
		}
	}
	return cfg
}

func (g topoGen) genKeys(topo topoFile, cfg map[addr.ISD]conf.TRC2) error {
	for ia := range topo.ASes {
		keys := g.genASKeys(ia.A, cfg[ia.I])
		var buf bytes.Buffer
		if err := keys.Encode(&buf); err != nil {
			return serrors.WithCtx(err, "ia", ia)
		}
		file := conf.KeysFile(g.Dirs.Root, ia)
		if err := pkicmn.WriteToFile(buf.Bytes(), file, 0644); err != nil {
			return serrors.WrapStr("unable to write key config", err, "ia", ia, "file", file)
		}
	}
	return nil
}

func (g topoGen) genASKeys(as addr.AS, cfg conf.TRC2) conf.Keys {
	keys := conf.Keys{
		Primary: make(map[trc.KeyType]map[scrypto.KeyVersion]conf.KeyMeta),
		Issuer:  make(map[cert.KeyType]map[scrypto.KeyVersion]conf.KeyMeta),
		AS: map[cert.KeyType]map[scrypto.KeyVersion]conf.KeyMeta{
			cert.SigningKey:    {1: {Algorithm: scrypto.Ed25519, Validity: g.Validity}},
			cert.RevocationKey: {1: {Algorithm: scrypto.Ed25519, Validity: g.Validity}},
			cert.EncryptionKey: {1: {Algorithm: scrypto.Curve25519xSalsa20Poly1305,
				Validity: g.Validity}},
		},
	}
	primary, ok := cfg.PrimaryASes[as]
	_ = ok
	if primary.Attributes.Contains(trc.Voting) {
		keys.Primary[trc.OnlineKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: g.Validity},
		}
		keys.Primary[trc.OfflineKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: g.Validity},
		}
	}
	if primary.Attributes.Contains(trc.Issuing) {
		keys.Primary[trc.IssuingKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: g.Validity},
		}
		keys.Issuer[cert.IssuingKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: g.Validity},
		}
	}
	return keys
}

func (g topoGen) genCerts(topo topoFile, cfg map[addr.ISD]conf.TRC2) error {
	// TODO(roosd): implement.
	return nil
}

// topoFile is used to parse the topology description.
type topoFile struct {
	ASes map[addr.IA]asEntry `yaml:"ASes"`
}

func (t topoFile) ISDs() map[addr.ISD]struct{} {
	m := make(map[addr.ISD]struct{})
	for ia := range t.ASes {
		m[ia.I] = struct{}{}
	}
	return m
}

func (t topoFile) Cores(isd addr.ISD) []addr.AS {
	var cores []addr.AS
	for ia, entry := range t.ASes {
		if ia.I == isd && entry.Core {
			cores = append(cores, ia.A)
		}
	}
	return cores
}

type asEntry struct {
	Core   bool    `yaml:"core"`
	Issuer addr.IA `yaml:"cert_issuer"`
}
