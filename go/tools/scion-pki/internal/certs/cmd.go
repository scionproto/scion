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
	Long: `'certs' can be used to generate and verify certificates for the SCION control plane PKI.

Selector:
    *-*: All ISDs and ASes under the root directory.
    X-*: All ASes in ISD X.
    X-Y: A specific AS X-Y, e.g. AS 1-ff00:0:110.

The subcommands expect the contents of the root directory to follow a predefined
file structure. See 'scion-pki help' for more information.
`,
}

var genIssuerCmd = &cobra.Command{
	Use:   "issuer",
	Short: "Generate the issuer certificate",
	Example: `  scion-pki certs issuer 1-ff00:0:110
  scion-pki certs issuer '*'
  scion-pki certs issuer 1-ff00:0:110 -d $SPKI_ROOT_DIR
  scion-pki certs issuer 1-ff00:0:110 --version 42`,
	Long: `'issuer' generates the issuer certificate based on the selector.

This command requires a valid issuer configuration file. Further, the referenced
TRC and its configuration file must be present.

See 'scion-pki help certs' for information on the selector.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g := issGen{
			Dirs:    pkicmn.GetDirs(),
			Version: scrypto.Version(version),
		}
		asMap, err := pkicmn.ProcessSelector(args[0])
		if err != nil {
			return serrors.WrapStr("unable to select target ISDs", err, "selector", args[0])
		}
		return g.Run(asMap)
	},
}

var genChainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Generate the certificate chain",
	Example: `  scion-pki certs chain 1-ff00:0:110
  scion-pki certs chain '*'
  scion-pki certs chain 1-ff00:0:110 -d $SPKI_ROOT_DIR
  scion-pki certs chain 1-ff00:0:110 --version 42`,
	Long: `'chain' generates the AS certificate and the resulting chain based on the selector.

This command requires a valid AS configuration file. Further, the referenced
issuer certificate and its configuration file must be present. For verification,
the TRC referenced by the issuer certificate must also be present.

See 'scion-pki help certs' for information on the selector.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g := chainGen{
			Dirs:    pkicmn.GetDirs(),
			Version: scrypto.Version(version),
		}
		asMap, err := pkicmn.ProcessSelector(args[0])
		if err != nil {
			return serrors.WrapStr("unable to select target ISDs", err, "selector", args[0])
		}
		return g.Run(asMap)
	},
}

var humanCmd = &cobra.Command{
	Use:   "human",
	Short: "Display human readable issuer certificates and certificate chains",
	Example: `  scion-pki certs human ISD1/ASff00_0_110/certs/ISD1-ASff00_0_110.crt
  scion-pki certs human ISD1/ASff00_0_110/certs/ISD1-ASff00_0_110.issuer
  scion-pki certs human ISD1/ASff00_0_110/certs/*`,
	Long: `'human' parses the provided issuer certificate and certificate chain files
and displays them in a human readable format.
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runHuman(args)
	},
}

func init() {
	Cmd.PersistentFlags().Uint64Var(&version, "version", 0,
		"certificate version (0 indicates newest)")
	Cmd.AddCommand(genChainCmd)
	Cmd.AddCommand(genIssuerCmd)
	Cmd.AddCommand(humanCmd)
}
