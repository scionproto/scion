// Copyright 2018 ETH Zurich
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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/trust"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runGenTrc(args []string) {
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		base.ErrorAndExit("Error: %s\n", err)
	}
	for isd := range asMap {
		if err = genTrc(isd); err != nil {
			base.ErrorAndExit("Error generating TRC: %s\n", err)
		}
	}
	os.Exit(0)
}

func genTrc(isd addr.ISD) error {
	dir := pkicmn.GetIsdPath(isd)
	// Check that isd.ini exists, otherwise skip directory.
	cpath := filepath.Join(dir, conf.IsdConfFileName)
	if _, err := os.Stat(cpath); os.IsNotExist(err) {
		return nil
	}
	iconf, err := conf.LoadIsdConf(dir)
	if err != nil {
		return common.NewBasicError("Error loading TRC conf", err)
	}
	fmt.Printf("Generating TRC for ISD %d\n", isd)
	t, err := newTrc(isd, iconf, dir)
	if err != nil {
		return err
	}
	raw, err := t.JSON(true)
	if err != nil {
		return common.NewBasicError("Error json-encoding TRC", err)
	}
	// Check if output directory exists.
	outDir := filepath.Join(dir, pkicmn.TRCsDir)
	if _, err = os.Stat(outDir); os.IsNotExist(err) {
		if err = os.MkdirAll(outDir, 0755); err != nil {
			return common.NewBasicError("Cannot create output dir", err, "path", outDir)
		}
	}
	fname := fmt.Sprintf(pkicmn.TrcNameFmt, isd, iconf.Trc.Version)
	return pkicmn.WriteToFile(raw, filepath.Join(outDir, fname), 0644)
}

func newTrc(isd addr.ISD, iconf *conf.Isd, path string) (*trc.TRC, error) {
	issuingTime := iconf.Trc.IssuingTime
	if issuingTime == 0 {
		issuingTime = uint64(time.Now().Unix())
	}
	t := &trc.TRC{
		CreationTime:   iconf.Trc.IssuingTime,
		Description:    iconf.Desc,
		ExpirationTime: issuingTime + uint64(iconf.Trc.Validity.Seconds()),
		GracePeriod:    uint64(iconf.Trc.GracePeriod),
		ISD:            isd,
		QuorumTRC:      iconf.Trc.QuorumTRC,
		Version:        iconf.Trc.Version,
		CoreASes:       make(map[addr.IA]*trc.CoreAS),
		Signatures:     make(map[string]common.RawBytes),
		RAINS:          &trc.Rains{},
		RootCAs:        make(map[string]*trc.RootCA),
		CertLogs:       make(map[string]*trc.CertLog),
	}
	// Load the online/offline root keys.
	var ases []coreAS
	for _, cia := range iconf.Trc.CoreIAs {
		var as coreAS
		var err error
		as.IA = cia
		aspath := pkicmn.GetAsPath(cia)
		cpath := filepath.Join(aspath, conf.AsConfFileName)
		if _, err = os.Stat(cpath); os.IsNotExist(err) {
			return nil, common.NewBasicError("Configuration file missing for AS", err, "path", aspath)
		}

		a, err := conf.LoadAsConf(aspath)
		if err != nil {
			return nil, common.NewBasicError("Error loading as.ini", err, "path", cpath)
		}

		if a.IssuerCert == nil {
			return nil, common.NewBasicError(fmt.Sprintf("'%s' section missing from as.ini",
				conf.IssuerSectionName), nil, "path", cpath)
		}

		if a.IssuerCert.OnlineKeyAlg == "" {
			as.OnlineKeyAlg = crypto.Ed25519
		} else {
			as.OnlineKeyAlg = a.IssuerCert.OnlineKeyAlg
		}

		if a.IssuerCert.OfflineKeyAlg == "" {
			as.OfflineKeyAlg = crypto.Ed25519
		} else {
			as.OfflineKeyAlg = a.IssuerCert.OfflineKeyAlg
		}

		online, err := trust.LoadKey(filepath.Join(aspath, pkicmn.KeysDir, trust.OnKeyFile))
		if err != nil {
			return nil, common.NewBasicError("Error loading online key", err)
		}
		as.Online = ed25519.PrivateKey(online)
		offline, err := trust.LoadKey(filepath.Join(aspath, pkicmn.KeysDir, trust.OffKeyFile))
		if err != nil {
			return nil, common.NewBasicError("Error loading offline key", err)
		}
		as.Offline = ed25519.PrivateKey(offline)
		ases = append(ases, as)
	}

	for _, as := range ases {
		t.CoreASes[as.IA] = &trc.CoreAS{
			OnlineKey:     common.RawBytes(as.Online.Public().(ed25519.PublicKey)),
			OnlineKeyAlg:  as.OnlineKeyAlg,
			OfflineKey:    common.RawBytes(as.Offline.Public().(ed25519.PublicKey)),
			OfflineKeyAlg: as.OfflineKeyAlg,
		}
	}
	// Sign the TRC.
	for _, as := range ases {
		if err := t.Sign(as.IA.String(), common.RawBytes(as.Online), crypto.Ed25519); err != nil {
			return nil, common.NewBasicError("Error signing TRC", err, "signer", as.IA)
		}
	}
	return t, nil
}

type coreAS struct {
	IA            addr.IA
	Online        ed25519.PrivateKey
	Offline       ed25519.PrivateKey
	OnlineKeyAlg  string
	OfflineKeyAlg string
}
