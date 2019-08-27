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
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

// asCfg holds the AS configuration including the from file system loaded
// private keys.
type asCfg struct {
	ASCfg *conf.ASCfg
	Keys  map[trc.KeyType][]byte
}

// KeyTypeToAlgo determines the algorithm for the key type.
func (cfg *asCfg) KeyTypeToAlgo(keyType trc.KeyType) string {
	switch keyType {
	case trc.OnlineKey:
		return cfg.ASCfg.Online
	case trc.OfflineKey:
		return cfg.ASCfg.Offline
	case trc.IssuingKey:
		return cfg.ASCfg.Issuing
	}
	return "none"
}

// loadPrimaryASes loads the primary ASes with their keys for the ASes in the
// whitelist. If the whitelist is empty, all primary ASes are loaded.
func loadPrimaryASes(isd addr.ISD, isdCfg *conf.ISDCfg, wl []addr.IA) (map[addr.AS]*asCfg, error) {
	ases := make(map[addr.AS][]trc.KeyType)
	for _, as := range isdCfg.VotingASes {
		ases[as] = []trc.KeyType{trc.OnlineKey, trc.OfflineKey}
	}
	for _, as := range isdCfg.IssuingASes {
		ases[as] = append(ases[as], trc.IssuingKey)
	}
	primaryASes := make(map[addr.AS]*asCfg)
	for as, keys := range ases {
		if len(wl) != 0 && !pkicmn.Contains(wl, addr.IA{I: isd, A: as}) {
			continue
		}
		ia := addr.IA{I: isd, A: as}
		cfg, err := loadASCfg(ia)
		if err != nil {
			return nil, err
		}
		for _, keyType := range keys {
			if cfg.Keys[keyType], err = loadKey(ia, keyType, cfg); err != nil {
				return nil, err
			}
		}
		primaryASes[as] = cfg
	}
	return primaryASes, nil
}

func loadASCfg(ia addr.IA) (*asCfg, error) {
	cfgPath := filepath.Join(pkicmn.GetAsPath(pkicmn.RootDir, ia), conf.ASConfFileName)
	cfg, err := conf.LoadASCfg(filepath.Dir(cfgPath))
	if err != nil {
		return nil, err
	}
	return &asCfg{ASCfg: cfg, Keys: make(map[trc.KeyType][]byte)}, nil
}

func loadKey(ia addr.IA, keyType trc.KeyType, cfg *asCfg) ([]byte, error) {
	var file string
	switch keyType {
	case trc.OnlineKey:
		file = keyconf.TRCOnlineKeyFile
	case trc.OfflineKey:
		file = keyconf.TRCOfflineKeyFile
	case trc.IssuingKey:
		file = keyconf.TRCIssuingKeyFile
	}
	key, err := keyconf.LoadKey(filepath.Join(pkicmn.GetAsPath(pkicmn.OutDir, ia),
		pkicmn.KeysDir, file), cfg.KeyTypeToAlgo(keyType))
	if err != nil {
		return nil, common.NewBasicError("unable to load key", err, "keyType", keyType)
	}
	return key, nil
}
