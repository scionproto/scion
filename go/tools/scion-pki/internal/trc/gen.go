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

func runGenTrc(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	isdDirs, _, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		cmd.Usage()
		os.Exit(2)
	}
	for _, dir := range isdDirs {
		if err = genTrc(dir); err != nil {
			base.ErrorAndExit("Error generating TRC: %s\n", err)
		}
	}
	os.Exit(0)
}

func genTrc(dir string) error {
	// Check that isd.ini exists, otherwise skip directory.
	cpath := filepath.Join(dir, conf.TrcConfFileName)
	if _, err := os.Stat(cpath); os.IsNotExist(err) {
		return nil
	}
	tconf, err := conf.LoadTrcConf(dir)
	if err != nil {
		return common.NewBasicError("Error loading TRC conf", err)
	}
	fmt.Printf("Generating TRC for ISD %d\n", tconf.Isd)
	t, err := newTrc(tconf, dir)
	if err != nil {
		return err
	}
	raw, err := t.JSON(true)
	if err != nil {
		return common.NewBasicError("Error json-encoding TRC", err)
	}
	fname := fmt.Sprintf(pkicmn.TrcNameFmt, tconf.Isd, tconf.Version)
	return pkicmn.WriteToFile(raw, filepath.Join(dir, fname), 0644)
}

func newTrc(tconf *conf.Trc, path string) (*trc.TRC, error) {
	t := &trc.TRC{
		CreationTime:   tconf.IssuingTime,
		Description:    tconf.Description,
		ExpirationTime: tconf.IssuingTime + tconf.Validity*24*60*60,
		GracePeriod:    tconf.GracePeriod,
		ISD:            tconf.Isd,
		QuorumTRC:      tconf.QuorumTRC,
		Version:        tconf.Version,
		CoreASes:       make(map[addr.ISD_AS]*trc.CoreAS),
		Signatures:     make(map[string]common.RawBytes),
		RAINS:          &trc.Rains{},
		RootCAs:        make(map[string]*trc.RootCA),
		CertLogs:       make(map[string]*trc.CertLog),
	}
	// Load the online/offline root keys.
	var ases []coreAS
	for _, cia := range tconf.CoreIAs {
		var as coreAS
		as.IA = *cia
		online, err := trust.LoadKey(filepath.Join(pkicmn.GetPath(cia), "keys", trust.OnKeyFile))
		if err != nil {
			return nil, common.NewBasicError("Error loading online key", err)
		}
		as.Online = ed25519.PrivateKey(online)
		offline, err := trust.LoadKey(filepath.Join(pkicmn.GetPath(cia), "keys", trust.OffKeyFile))
		if err != nil {
			return nil, common.NewBasicError("Error loading offline key", err)
		}
		as.Offline = ed25519.PrivateKey(offline)
		ases = append(ases, as)
	}
	for _, as := range ases {
		t.CoreASes[as.IA] = &trc.CoreAS{
			OnlineKey:     common.RawBytes(as.Online.Public().(ed25519.PublicKey)),
			OnlineKeyAlg:  crypto.Ed25519,
			OfflineKey:    common.RawBytes(as.Offline.Public().(ed25519.PublicKey)),
			OfflineKeyAlg: crypto.Ed25519,
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
	IA      addr.ISD_AS
	Online  ed25519.PrivateKey
	Offline ed25519.PrivateKey
}
