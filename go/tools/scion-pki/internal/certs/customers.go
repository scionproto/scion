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
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runCustomers(args []string) {
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		pkicmn.ErrorAndExit("Error: %s\n", err)
	}
	cfgs, err := loadASConfigs(args[0])
	if err != nil {
		pkicmn.ErrorAndExit("Error loading configs: %s\n", err)
	}
	for isd, ases := range asMap {
		iconf, err := conf.LoadIsdConf(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
		if err != nil {
			pkicmn.ErrorAndExit("Error reading isd.ini: %s\n", err)
		}
		for _, ia := range ases {
			if !pkicmn.Contains(iconf.Trc.CoreIAs, ia) {
				continue
			}
			if err := copyCustomers(ia, cfgs[isd]); err != nil {
				pkicmn.ErrorAndExit("Error copying customer keys for %s: %s\n", ia, err)
			}
		}
	}
	os.Exit(0)
}

func copyCustomers(ia addr.IA, cfgs map[addr.IA]*conf.As) error {
	custDir := filepath.Join(pkicmn.GetAsPath(pkicmn.RootDir, ia), "customers")
	if err := os.MkdirAll(custDir, 0755); err != nil {
		return common.NewBasicError("unable to make customers dir", err, "path", custDir)
	}
	for cust, cfg := range cfgs {
		if !cfg.AsCert.IssuerIA.Equal(ia) {
			continue
		}
		search := fmt.Sprintf("ISD%d-AS%s-V*.crt", cust.I, cust.A.FileFmt())
		pattern := filepath.Join(pkicmn.GetAsPath(pkicmn.RootDir, cust), pkicmn.CertsDir, search)
		chains, err := filepath.Glob(pattern)
		if err != nil {
			return common.NewBasicError("unable to glob chains", err, "pattern", pattern)
		}
		for _, chainFile := range chains {
			c, err := cert.ChainFromFile(chainFile, false)
			if err != nil {
				return common.NewBasicError("unable to load chain", err, "file", chainFile)
			}
			_, name := filepath.Split(chainFile)
			keyName := fmt.Sprintf("%s.key", strings.TrimSuffix(name, filepath.Ext(name)))
			file := filepath.Join(custDir, keyName)
			key := base64.StdEncoding.EncodeToString(c.Leaf.SubjectSignKey)
			if err = pkicmn.WriteToFile([]byte(key), file, 0644); err != nil {
				return common.NewBasicError("Error writing customer key", err, "file", file)
			}
		}
	}
	return nil
}

func loadASConfigs(selector string) (map[addr.ISD]map[addr.IA]*conf.As, error) {
	isd, _, err := pkicmn.ParseSelector(selector)
	if err != nil {
		return nil, common.NewBasicError("unable to parse selector", err)
	}
	asMap, err := pkicmn.ProcessSelector(isd)
	if err != nil {
		return nil, err
	}
	cfgs := make(map[addr.ISD]map[addr.IA]*conf.As)
	for isd, ases := range asMap {
		cfgs[isd] = make(map[addr.IA]*conf.As)
		for _, ia := range ases {
			confdir := pkicmn.GetAsPath(pkicmn.RootDir, ia)
			path := filepath.Join(confdir, conf.AsConfFileName)
			if _, err = os.Stat(path); os.IsNotExist(err) {
				pkicmn.QuietPrint("Skipping %s. Missing %s\n", ia, path)
				continue
			}
			cfg, err := conf.LoadAsConf(confdir)
			if err != nil {
				return nil, common.NewBasicError("unable to load as.ini", err, "path", path)
			}
			cfgs[isd][ia] = cfg
		}
	}
	return cfgs, nil
}
