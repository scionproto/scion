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
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
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
	if err := g.genCerts(topo); err != nil {
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

func (g topoGen) genTRCs(topo topoFile) (map[addr.ISD]conf.TRC, error) {
	trcs := make(map[addr.ISD]conf.TRC)
	for isd := range topo.ISDs() {
		cfg, err := g.genTRC(isd, topo)
		if err != nil {
			return nil, serrors.WithCtx(err, "isd", isd)
		}
		trcs[isd] = cfg
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

func (g topoGen) genTRC(isd addr.ISD, topo topoFile) (conf.TRC, error) {
	primaries := topo.Primaries(isd)
	if primaries.Count(trc.Voting) == 0 {
		return conf.TRC{}, serrors.New("no voting AS specified")
	}
	if primaries.Count(trc.Issuing) == 0 {
		return conf.TRC{}, serrors.New("no issuing AS specified")
	}
	reset := true
	cfg := conf.TRC{
		Description: fmt.Sprintf("ISD %d", isd),
		Version:     1,
		BaseVersion: 1,
		// XXX(roosd): Choose quorum according to your security needs.
		// This simply serves an example.
		VotingQuorum:      uint16(primaries.Count(trc.Voting)/2 + 1),
		TrustResetAllowed: &reset,
		Votes:             []addr.AS{},
		Validity:          g.Validity,
		PrimaryASes:       make(map[addr.AS]conf.Primary),
	}
	for _, primaryAS := range primaries {
		cfg.PrimaryASes[primaryAS.AS] = primaryAS.ToConf()
	}
	return cfg, nil
}

func (g topoGen) genKeys(topo topoFile, cfg map[addr.ISD]conf.TRC) error {
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

func (g topoGen) genASKeys(as addr.AS, cfg conf.TRC) conf.Keys {
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
		keys.Primary[trc.VotingOnlineKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: g.Validity},
		}
		keys.Primary[trc.VotingOfflineKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: g.Validity},
		}
	}
	if primary.Attributes.Contains(trc.Issuing) {
		keys.Primary[trc.IssuingGrantKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: g.Validity},
		}
		keys.Issuer[cert.IssuingKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: g.Validity},
		}
	}
	return keys
}

func (g topoGen) genCerts(topo topoFile) error {
	if err := g.genIssuerCerts(topo); err != nil {
		return serrors.WrapStr("unable to generate issuer certificates", err)
	}
	if err := g.genASCerts(topo); err != nil {
		return serrors.WrapStr("unable to generate AS certificates", err)
	}
	return nil
}

func (g topoGen) genIssuerCerts(topo topoFile) error {
	for ia, entry := range topo.ASes {
		if !entry.Issuing {
			continue
		}
		cfg := g.genIssuerCert(ia)
		var buf bytes.Buffer
		if err := cfg.Encode(&buf); err != nil {
			return serrors.WithCtx(err, "ia", ia)
		}
		file := conf.IssuerFile(g.Dirs.Root, ia, cfg.Version)
		if err := pkicmn.WriteToFile(buf.Bytes(), file, 0644); err != nil {
			return serrors.WrapStr("unable to write issuer config", err, "ia", ia, "file", file)
		}
	}
	return nil
}

func (g topoGen) genIssuerCert(ia addr.IA) conf.Issuer {
	issKey := scrypto.KeyVersion(1)
	cfg := conf.Issuer{
		Description:            fmt.Sprintf("Issuer certificate %s", ia),
		Version:                1,
		IssuingGrantKeyVersion: &issKey,
		RevocationKeyVersion:   nil,
		TRCVersion:             1,
		OptDistPoints:          []addr.IA{},
		Validity:               g.Validity,
	}
	return cfg
}

func (g topoGen) genASCerts(topo topoFile) error {
	for ia, entry := range topo.ASes {
		issuer := entry.Issuer
		if entry.Issuing {
			issuer = ia
		}
		cfg := g.genASCert(ia, issuer)
		var buf bytes.Buffer
		if err := cfg.Encode(&buf); err != nil {
			return serrors.WithCtx(err, "ia", ia)
		}
		file := conf.ASFile(g.Dirs.Root, ia, cfg.Version)
		if err := pkicmn.WriteToFile(buf.Bytes(), file, 0644); err != nil {
			return serrors.WrapStr("unable to write AS config", err, "ia", ia, "file", file)
		}
	}
	return nil
}

func (g topoGen) genASCert(ia, issuer addr.IA) conf.AS {
	sigKey, encKey, revKey := scrypto.KeyVersion(1), scrypto.KeyVersion(1), scrypto.KeyVersion(1)
	cfg := conf.AS{
		Description:          fmt.Sprintf("AS certificate %s", ia),
		Version:              1,
		SigningKeyVersion:    &sigKey,
		EncryptionKeyVersion: &encKey,
		RevocationKeyVersion: &revKey,
		IssuerIA:             issuer,
		IssuerCertVersion:    1,
		OptDistPoints:        []addr.IA{},
		Validity:             g.Validity,
	}
	return cfg
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

func (t topoFile) Primaries(isd addr.ISD) primaryASes {
	var primaries primaryASes
	for ia, entry := range t.ASes {
		if ia.I == isd && entry.Primary() {
			primaries = append(primaries, primaryAS{AS: ia.A, asEntry: entry})
		}
	}
	return primaries
}

type asEntry struct {
	Authoritative bool    `yaml:"authoritative"`
	Core          bool    `yaml:"core"`
	Issuing       bool    `yaml:"issuing"`
	Voting        bool    `yaml:"voting"`
	Issuer        addr.IA `yaml:"cert_issuer"`
}

func (e asEntry) Primary() bool {
	return e.Authoritative || e.Core || e.Issuing || e.Voting
}

type primaryAS struct {
	AS addr.AS
	asEntry
}

func (p primaryAS) ToConf() conf.Primary {
	cp := conf.Primary{}
	if p.Authoritative {
		cp.Attributes = append(cp.Attributes, trc.Authoritative)
	}
	if p.Core {
		cp.Attributes = append(cp.Attributes, trc.Core)
	}
	if p.Issuing {
		iss := scrypto.KeyVersion(1)
		cp.Attributes = append(cp.Attributes, trc.Issuing)
		cp.IssuingGrantKeyVersion = &iss
	}
	if p.Voting {
		on, off := scrypto.KeyVersion(1), scrypto.KeyVersion(1)
		cp.Attributes = append(cp.Attributes, trc.Voting)
		cp.VotingOnlineKeyVersion = &on
		cp.VotingOfflineKeyVersion = &off
	}
	return cp
}

type primaryASes []primaryAS

func (p primaryASes) Count(attr trc.Attribute) int {
	c := 0
	for _, as := range p {
		switch {
		case attr == trc.Authoritative && as.Authoritative:
			c++
		case attr == trc.Core && as.Core:
			c++
		case attr == trc.Issuing && as.Issuing:
			c++
		case attr == trc.Voting && as.Voting:
			c++
		}
	}
	return c
}
