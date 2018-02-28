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

// Package trc provides a generator for Trust Root Configuration (TRC) files for the SCION
// control plane PKI.
package trc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/trust"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var CmdTrc = &base.Command{
	Name:      "trc",
	Run:       runTrc,
	UsageLine: "trc [-h] gen [<flags>] selector",
	Short:     "Generate TRCs for the SCION control plane PKI",
	Long: `
'trc' can be used to generate Trust Root Configuration (TRC) files used in the SCION control
plane PKI.

The following subcommands are available:
	gen
		Used to generate new TRCs.

The following flags are available:
	-d
		The root directory of on which 'scion-pki' operates.
	-f
		Overwrite existing TRCs.

The following selectors are available:
	all
		Apply command to all ISDs under the root directory.
	isd <id>
		Apply command to a given ISD.
`,
}

func init() {
	CmdTrc.Flag.StringVar(&pkicmn.RootDir, "d", ".", "")
	CmdTrc.Flag.BoolVar(&pkicmn.Force, "f", false, "")
}

func runTrc(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	subCmd := args[0]
	cmd.Flag.Parse(args[1:])
	switch subCmd {
	case "gen":
		runGenTrc(cmd, cmd.Flag.Args())
	default:
		fmt.Fprintf(os.Stderr, "unrecognized subcommand '%s'\n", args[0])
		fmt.Fprintf(os.Stderr, "run 'scion-pki trc -h' for help.\n")
		os.Exit(2)
	}
	os.Exit(0)
}

func runGenTrc(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	top, err := pkicmn.ProcessSelector(args[0], args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		cmd.Usage()
		os.Exit(2)
	}
	if err := filepath.Walk(top, visitTrc); err != nil && err != filepath.SkipDir {
		base.ErrorAndExit("%s\n", err)
	}
	os.Exit(0)
}

func visitTrc(path string, info os.FileInfo, visitError error) error {
	if visitError != nil {
		return visitError
	}
	if !info.IsDir() || !strings.HasPrefix(info.Name(), "ISD") {
		return nil
	}
	conf, err := loadTrcConf(filepath.Join(path, trcConfFile))
	if err != nil {
		return common.NewBasicError("Error loading TRC conf", err)
	}
	t, err := genTrc(conf, path)
	if err != nil {
		return err
	}
	raw, err := t.JSON(true)
	if err != nil {
		return common.NewBasicError("Error json-encoding TRC", err)
	}
	fname := fmt.Sprintf(pkicmn.TrcNameFmt, conf.Isd, conf.Version)
	if err = pkicmn.WriteToFile(raw, filepath.Join(path, fname), 0644); err != nil {
		return err
	}
	return filepath.SkipDir
}

func genTrc(conf *trcConf, path string) (*trc.TRC, error) {
	t := &trc.TRC{
		CreationTime:   conf.IssuingTime,
		Description:    conf.Description,
		ExpirationTime: conf.IssuingTime + conf.Validity*24*60*60,
		GracePeriod:    conf.GracePeriod,
		ISD:            conf.Isd,
		QuorumTRC:      conf.QuorumTRC,
		Version:        conf.Version,
		CoreASes:       make(map[addr.ISD_AS]*trc.CoreAS),
		Signatures:     make(map[string]common.RawBytes),
		RAINS:          &trc.Rains{},
		RootCAs:        make(map[string]*trc.RootCA),
		CertLogs:       make(map[string]*trc.CertLog),
	}
	// Load the online/offline root keys.
	var ases []coreAS
	for _, cia := range conf.CoreIAs {
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
