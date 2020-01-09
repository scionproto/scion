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

package trcs

import (
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var version uint64

// TODO(roosd): Expand help text with the new TRC configuration format.

var Cmd = &cobra.Command{
	Use:   "trcs",
	Short: "Generate TRCs for the SCION control plane PKI",
	Long: `'trc' can be used to generate Trust Root Configuration (TRC) files used in the
SCION control plane PKI.

Generating a TRC can be split into three phases:
1. 'proto': Generate the prototype TRC that contains the payload part of the signed TRC.
2. 'sign': Sign the payload with the respective private keys.
3. 'combine': Combine the signatures and the payload to a fully signed TRC.

In case the caller has access to all private keys, the caller can use a
short-cut command that generates the signed TRC in one call: 'gen'.

Selector:
    *: All ISDs under the root directory.
    X: ISD X.

The subcommands expect the contents of the root directory to follow a predefined
file structure. See 'scion-pki help' for more information.
`,
}

var gen = &cobra.Command{
	Use:   "gen",
	Short: "Generate new TRCs",
	Example: `  scion-pki trcs gen 1
  scion-pki trcs gen '*' -d $SPKI_ROOT_DIR
  scion-pki trcs gen '*' --version 42`,
	Long: `'gen' generates the TRCS based on the selector.

This command coalesces the prototype, sign and combine step of the trc generation.

This command requires a valid TRC configuration file. Further, all private keys
for the signing ASes must be present. For non-base TRCs, the previous TRC must
be present.

See 'scion-pki help trcs' for information on the selector.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g := fullGen{
			Dirs:    pkicmn.GetDirs(),
			Version: scrypto.Version(version),
		}
		asMap, err := pkicmn.ProcessSelector(args[0])
		if err != nil {
			return serrors.WrapStr("unable to select target ISDs", err, "selector", args[0])
		}
		if err := g.Run(asMap); err != nil {
			return serrors.WrapStr("unable to generate prototype TRCs", err)
		}
		return nil
	},
}

var proto = &cobra.Command{
	Use:   "proto",
	Short: "Generate new proto TRCs",
	Example: `  scion-pki trcs proto 1
  scion-pki trcs proto '*' -d $SPKI_ROOT_DIR
  scion-pki trcs proto '*' --version 42`,
	Long: `'proto' generates the prototype TRCs based on the selector.

This command requires a valid TRC configuration file. Further, the private or
public key for each key referenced in the TRC must be present. For non-base TRCs,
the previous TRC must be present.

The prototype TRC is stored in a sub-directory of 'trcs'.

See 'scion-pki help trcs' for information on the selector.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g := protoGen{
			Dirs:    pkicmn.GetDirs(),
			Version: scrypto.Version(version),
		}
		asMap, err := pkicmn.ProcessSelector(args[0])
		if err != nil {
			return serrors.WrapStr("unable to select target ISDs", err, "selector", args[0])
		}
		if err := g.Run(asMap); err != nil {
			return serrors.WrapStr("unable to generate prototype TRCs", err)
		}
		return nil
	},
}

var sign = &cobra.Command{
	Use:   "sign",
	Short: "Sign the proto TRCs",
	Example: `  scion-pki trcs sign 1-ff00:0:110
  scion-pki trcs sign '1-*' -d $SPKI_ROOT_DIR
  scion-pki trcs sign '*' --version 42`,
	Long: `'sign' generates the partial signatures for TRCs based on the selector.

This command requires a valid TRC configuration file. Further, the private keys
that issue the votes and/or proof of possessions are required. For non-base TRCs,
the previous TRC must be present.

Selector:
    *-*: All ASes under the root directory.
    X-*: All ASes in ISD X.
    X-Y: A specific AS X-Y, e.g. AS 1-ff00:0:110.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g := signatureGen{
			Dirs:    pkicmn.GetDirs(),
			Version: scrypto.Version(version),
		}
		asMap, err := pkicmn.ProcessSelector(args[0])
		if err != nil {
			return serrors.WrapStr("unable to select target ISDs", err, "selector", args[0])
		}
		if err := g.Run(asMap); err != nil {
			return serrors.WrapStr("unable to sign TRCs", err)
		}
		return nil
	},
}

var combine = &cobra.Command{
	Use:   "combine",
	Short: "Combine the proto TRCs with their signatures",
	Example: `  scion-pki trcs combine 1
  scion-pki trcs combine '*' -d $SPKI_ROOT_DIR
  scion-pki trcs combine '*' --version 42`,
	Long: `'combine' generates a new signed TRC from the prototype TRC and the signatures
based on the selector.

This command requires the prototype TRC and all partial signatures. For non-base
TRCs, the previous TRC must be present.

See 'scion-pki help trcs' for information on the selector.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g := combiner{
			Dirs:    pkicmn.GetDirs(),
			Version: scrypto.Version(version),
		}
		asMap, err := pkicmn.ProcessSelector(args[0])
		if err != nil {
			return serrors.WrapStr("unable to select target ISDs", err, "selector", args[0])
		}
		if err := g.Run(asMap); err != nil {
			return serrors.WrapStr("unable to combine TRCs", err)
		}
		return nil
	},
}

var human = &cobra.Command{
	Use:   "human",
	Short: "Display human readable",
	Example: `  scion-pki trcs human ISD1/trcs/ISD1-V1.trc
  scion-pki trcs human ISD1/trcs/*`,
	Long: `'human' parses the provided TRCs and displays them in a human readable format.
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runHuman(args); err != nil {
			return common.NewBasicError("unable to display human TRCs", err)
		}
		return nil
	},
}

func init() {
	Cmd.PersistentFlags().Uint64Var(&version, "version", 0, "TRC version (0 indicates newest)")
	Cmd.AddCommand(gen)
	Cmd.AddCommand(proto)
	Cmd.AddCommand(sign)
	Cmd.AddCommand(combine)
	Cmd.AddCommand(human)
}
