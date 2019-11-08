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
	Long: `
'trc' can be used to generate Trust Root Configuration (TRC) files used in the SCION control
plane PKI.

Generating a TRC can be split into three phases:
1. 'proto': Generate the prototype TRC that contains the payload part of the signed TRC.
2. 'sign': Sign the payload with the respective private keys.
3. 'combine': Combine the signatures and the payload to a fully signed TRC.

In case the caller has access to all private keys, the caller can use a short-cut command
that generates the signed TRC in one call: 'gen'.

Selector:
	*
		All ISDs under the root directory.
	X
		ISD X.
`,
}

var proto = &cobra.Command{
	Use:   "proto",
	Short: "Generate new proto TRCs",
	Long: `
	'proto' generates new prototype TRCs from the ISD configs. They need to be signed
	using the sign command.
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
	Long: `
	'sign' generates new signatures for the proto TRCs.
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

var human = &cobra.Command{
	Use:   "human",
	Short: "Display human readable",
	Long: `
	'human' parses the provided TRCs and displays them in a human readable format.
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
	Cmd.AddCommand(proto)
	Cmd.AddCommand(sign)
	Cmd.AddCommand(human)
}
