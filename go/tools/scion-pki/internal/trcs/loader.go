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
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

type loader struct {
	Dirs    pkicmn.Dirs
	Version scrypto.Version
}

func (l loader) LoadConfigs(isds []addr.ISD) (map[addr.ISD]conf.TRC, error) {
	cfgs := make(map[addr.ISD]conf.TRC)
	for _, isd := range isds {
		file, err := l.selectConfig(isd)
		if err != nil {
			return nil, serrors.WrapStr("unable to select config", err, "isd", isd)
		}
		cfg, err := conf.LoadTRC(file)
		if err != nil {
			return nil, serrors.WrapStr("unable to load TRC config", err, "isd", isd)
		}
		cfgs[isd] = cfg
	}
	return cfgs, nil
}

func (l loader) selectConfig(isd addr.ISD) (string, error) {
	if l.Version != scrypto.LatestVer {
		return conf.TRCFile(l.Dirs.Root, isd, l.Version), nil
	}
	files, err := filepath.Glob(conf.AllTRCFiles(l.Dirs.Root, isd))
	if err != nil {
		return "", serrors.WrapStr("unable to search all available versions", err)
	}
	if len(files) == 0 {
		return "", serrors.WrapStr("no TRC config files found", err)
	}
	max, err := l.findMaxVersion(files)
	if err != nil {
		return "", serrors.WrapStr("unable to find max version", err)
	}
	return conf.TRCFile(l.Dirs.Root, isd, max), nil
}

func (l loader) findMaxVersion(files []string) (scrypto.Version, error) {
	re := regexp.MustCompile(`trc-v(\d*)\.toml$`)
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

func (l loader) LoadProtos(cfgs map[addr.ISD]conf.TRC) (map[addr.ISD]signedMeta, error) {
	protos := make(map[addr.ISD]signedMeta)
	for isd, cfg := range cfgs {
		file := ProtoFile(l.Dirs.Out, isd, cfg.Version)
		raw, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, serrors.WrapStr("unable to read prototype TRC", err, "file", file)
		}
		signed, err := trc.ParseSigned(raw)
		if err != nil {
			return nil, serrors.WrapStr("unable to parse prototype TRC", err, "file", file)
		}
		protos[isd] = signedMeta{Signed: signed, Version: cfg.Version}
	}
	return protos, nil
}

func (l loader) LoadParts(protos map[addr.ISD]signedMeta) (map[addr.ISD]trcParts, error) {
	all := make(map[addr.ISD]trcParts)
	for isd, proto := range protos {
		parts := make(trcParts)
		fnames, err := filepath.Glob(AllPartsFiles(l.Dirs.Out, isd, proto.Version))
		if err != nil {
			return nil, serrors.WrapStr("unable to list all signed parts", err, "isd", isd)
		}
		for _, fname := range fnames {
			raw, err := ioutil.ReadFile(fname)
			if err != nil {
				return nil, serrors.WrapStr("unable to read signed part", err, "file", fname)
			}
			signed, err := trc.ParseSigned(raw)
			if err != nil {
				return nil, serrors.WrapStr("unable to parse signed part", err, "file", fname)
			}
			parts[fname] = signed
		}
		all[isd] = parts
	}
	return all, nil
}
