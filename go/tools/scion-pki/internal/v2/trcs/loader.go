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
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

type loader struct {
	Dirs    pkicmn.Dirs
	Version scrypto.Version
}

func (l loader) LoadConfigs(asMap map[addr.ISD][]addr.IA) (map[addr.ISD]conf.TRC2, error) {
	cfgs := make(map[addr.ISD]conf.TRC2)
	for isd := range asMap {
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
	re := regexp.MustCompile(`trc-v(\d*)\.toml$`)
	var max uint64
	for _, file := range files {
		ver, err := strconv.ParseUint(re.FindStringSubmatch(file)[1], 10, 64)
		if err != nil {
			return "", serrors.WrapStr("unable to parse version", err, "file", file)
		}
		if ver > max {
			max = ver
		}
	}
	return conf.TRCFile(l.Dirs.Root, isd, scrypto.Version(max)), nil
}
