// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var version uint64

var Cmd = &cobra.Command{
	Use:   "certs",
	Short: "Interact with certificates for the SCION control plane PKI.",
	Long: `
'certs' can be used to generate and verify certificates for the SCION control plane PKI.

Selector:
	*-*
		All ISDs and ASes under the root directory.
	X-*
		All ASes in ISD X.
	X-Y
		A specific AS X-Y, e.g. AS 1-ff00:0:300

'certs' needs to be pointed to the root directory where all keys and certificates are
stored on disk (-d flag). It expects the contents of the root directory to follow
a predefined structure:
	<root>/
		ISD1/
			trc-v1.toml
			ASff00_0_110/
				as-v1.toml
				issuer-v1.toml
				keys.toml
				certs/
				keys/
			ASff00_0_120/
			...
		ISD2/
			ASff00_0_210/
			...
		...
`,
}

var genIssuerCmd = &cobra.Command{
	Use:   "issuer",
	Short: "Generate the issuer certificate",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g := issGen{
			Dirs:    pkicmn.GetDirs(),
			Version: scrypto.Version(version),
		}
		asMap, err := pkicmn.ProcessSelector(args[0])
		if err != nil {
			return serrors.WrapStr("unable to select target ISDs", err, "selector", args[0])
		}
		if err := g.Run(asMap); err != nil {
			return serrors.WrapStr("unable to generate issuer certificates", err)
		}
		return nil
	},
}

func init() {
	Cmd.AddCommand(genIssuerCmd)
}
