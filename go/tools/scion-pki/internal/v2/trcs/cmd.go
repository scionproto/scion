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
)

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
'trc' needs to be pointed to the root directory where all keys and certificates are
stored on disk (-d flag). It expects the contents of the root directory to follow
a predefined structure:
	<root>/
		ISD1/
			isd.ini
			AS1/
			AS2/
			...
		ISD2/
			isd.ini
			AS1/
			...
		...
isd.ini contains the preconfigured parameters according to which 'trc' generates
the TRCs. It follows the ini format and can contain only the default section with
the following values:
	Description [required]
		arbitrary non-empty string used to describe the ISD/TRC
and a section 'TRC' with the following values:
	Version [required]
		integer representing the version of the TRC
	BaseVersion [required]
		integer representing the base version of the TRC
	VotingQuorum [required]
		integer representing the number of voting ASes needed to sign an updated TRC.
	GracePeriod [required]
		duration string indicating how long the previous TRC is still valid.
		Must be 0s for base TRC.
	TrustResetAllowed [required]
		boolean indicating whether trust resets are allowed for this ISD.
	NotBefore [optional]
		integer representing the not_before time in the TRC represented as seconds
		since UNIX epoch. If 0 will be set to now.
	Validity [required]
		duration string determining the validity of the TRC, e.g., 180d or 36h.
	AuthoritativeASes [required]
		comma-separated list of AS identifiers representing the authoritative
		ASes of the ISD, e.g., ff00:0:110,ff00:0:120.
	CoreASes [required]
		comma-separated list of AS identifiers representing the core
		ASes of the ISD, e.g., ff00:0:110,ff00:0:120.
	IssuingASes [required]
		comma-separated list of AS identifiers representing the issuing
		ASes of the ISD, e.g., ff00:0:110,ff00:0:120.
	VotingASes [required]
		comma-separated list of AS identifiers representing the voting
		ASes of the ISD, e.g., ff00:0:110,ff00:0:120.
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
		if err := runProto(args[0]); err != nil {
			return common.NewBasicError("unable to generate prototype TRC", err)
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
		if err := runSign(args[0]); err != nil {
			return common.NewBasicError("unable to sign TRC", err)
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
	Run: func(cmd *cobra.Command, args []string) {
		runHuman(args)
	},
}

func init() {
	Cmd.AddCommand(proto)
	Cmd.AddCommand(sign)
	Cmd.AddCommand(human)
}
