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

package certs

import (
	"errors"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var errNoFilesFound = serrors.New("no config files found")

type loader struct {
	Dirs    pkicmn.Dirs
	Version scrypto.Version
}

func (l loader) LoadIssuerConfigs(asMap pkicmn.ASMap) (map[addr.IA]conf.Issuer, error) {
	s := selector{
		File:  conf.IssuerFile,
		All:   conf.AllIssuerFiles,
		Regex: `issuer-v(\d*)\.toml$`,
	}
	cfgs := make(map[addr.IA]conf.Issuer)
	for _, ias := range asMap {
		for _, ia := range ias {
			file, err := l.selectConfig(ia, s)
			switch {
			case errors.Is(err, errNoFilesFound):
				pkicmn.QuietPrint("Ignoring AS without issuer certificate config: %s\n", ia)
				continue
			case err != nil:
				return nil, serrors.WrapStr("unable to select config", err, "ia", ia)
			}
			cfg, err := conf.LoadIssuer(file)
			if err != nil {
				return nil, serrors.WithCtx(err, "ia", ia)
			}
			cfgs[ia] = cfg
		}
	}
	return cfgs, nil
}

func (l loader) LoadASConfigs(asMap pkicmn.ASMap) (map[addr.IA]conf.AS, error) {
	s := selector{
		File:  conf.ASFile,
		All:   conf.AllASFiles,
		Regex: `as-v(\d*)\.toml$`,
	}
	cfgs := make(map[addr.IA]conf.AS)
	for _, ias := range asMap {
		for _, ia := range ias {
			file, err := l.selectConfig(ia, s)
			if err != nil {
				return nil, serrors.WrapStr("unable to select config", err, "ia", ia)
			}
			cfg, err := conf.LoadAS(file)
			if err != nil {
				return nil, serrors.WithCtx(err, "ia", ia)
			}
			cfgs[ia] = cfg
		}
	}
	return cfgs, nil
}

func (l loader) selectConfig(ia addr.IA, s selector) (string, error) {
	if l.Version != scrypto.LatestVer {
		return s.File(l.Dirs.Root, ia, l.Version), nil
	}
	files, err := filepath.Glob(s.All(l.Dirs.Root, ia))
	if err != nil {
		return "", serrors.WrapStr("unable to search all available versions", err)
	}
	if len(files) == 0 {
		return "", errNoFilesFound
	}
	max, err := findMaxVersion(files, s.Regex)
	if err != nil {
		return "", serrors.WrapStr("unable to find max version", err)
	}
	return s.File(l.Dirs.Root, ia, max), nil
}

func findMaxVersion(files []string, matcher string) (scrypto.Version, error) {
	re := regexp.MustCompile(matcher)
	var max uint64
	for _, file := range files {
		ver, err := strconv.ParseUint(re.FindStringSubmatch(file)[1], 10, 64)
		if err != nil {
			return 0, serrors.WrapStr("unable to parse version", err, "file", file)
		}
		if ver > max {
			max = ver
		}
	}
	return scrypto.Version(max), nil
}

type selector struct {
	File  func(string, addr.IA, scrypto.Version) string
	All   func(string, addr.IA) string
	Regex string
}
