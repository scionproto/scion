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

package certs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runVerify(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	for _, certPath := range args {
		// Load file.
		raw, err := ioutil.ReadFile(certPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %s", certPath, err)
			continue
		}
		chain, err := cert.ChainFromRaw(raw, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing chain: %s\n", err)
			continue
		}
		if err = verifyChain(chain, chain.Leaf.Subject); err != nil {
			fmt.Printf("Verification of %s FAILED. Reason: %s\n", certPath, err)
			continue
		}
		fmt.Printf("Verification of %s SUCCEEDED.\n", certPath)
	}
}

func verifyChain(chain *cert.Chain, subject *addr.ISD_AS) error {
	// Load corresponding TRC.
	t, err := loadTRC(subject, chain.Leaf.TRCVersion)
	if err != nil {
		return err
	}
	return chain.Verify(subject, t)
}

func loadTRC(subject *addr.ISD_AS, version uint64) (*trc.TRC, error) {
	fname := fmt.Sprintf(pkicmn.TrcNameFmt, subject.I, version)
	trcPath := filepath.Join(pkicmn.RootDir, fmt.Sprintf("ISD%d", subject.I), fname)
	trcRaw, err := ioutil.ReadFile(trcPath)
	if err != nil {
		return nil, err
	}
	t, err := trc.TRCFromRaw(trcRaw, false)
	if err != nil {
		return nil, err
	}
	return t, nil
}
