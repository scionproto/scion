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

package keys

import (
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var Cmd = &cobra.Command{
	Use:   "keys",
	Short: "Generate keys for the SCION control plane PKI.",
	Long: `
'keys' can be used to generate all the necessary keys used in the SCION control plane PKI.

Selector:
    *-*: All ISDs and ASes under the root directory.
    X-*: All ASes in ISD X.
    X-Y: A specific AS X-Y, e.g. AS 1-ff00:0:110.

The subcommands expect the contents of the root directory to follow a predefined
file structure. See 'scion-pki help' for more information.
`,
}

var privateCmd = &cobra.Command{
	Use:   "private",
	Short: "Generate private keys",
	Example: `  scion-pki keys private 1-ff00:0:110
  scion-pki keys private '*'
  scion-pki keys private 1-ff00:0:110 -d $SPKI_ROOT_DIR`,
	Long: `'private' generates the private keys based on the selector.
Already existing keys are not overwritten, unless the force flag is enabled.
This command requires a valid keys.toml.

See 'scion-pki help keys' for information on the selector.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g := privGen{Dirs: pkicmn.GetDirs()}
		asMap, err := pkicmn.ProcessSelector(args[0])
		if err != nil {
			return serrors.WrapStr("invalid selector", err)
		}
		if err := g.Run(asMap); err != nil {
			return err
		}
		return nil
	},
}

var publicCmd = &cobra.Command{
	Use:   "public",
	Short: "Generate public keys",
	Example: `  scion-pki keys public 1-ff00:0:110
  scion-pki keys public '*'
  scion-pki keys public 1-ff00:0:110 -d $SPKI_ROOT_DIR`,
	Long: `'public' generates the public keys based on the selector.
For all ASes covered by the selector, the public keys are derived from the existing
private keys in the 'keys' directory. Non-existent private keys are not generated.

See 'scion-pki help keys' for information on the selector.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g := pubGen{Dirs: pkicmn.GetDirs()}
		asMap, err := pkicmn.ProcessSelector(args[0])
		if err != nil {
			return serrors.WrapStr("invalid selector", err)
		}
		if err := g.Run(asMap); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	Cmd.AddCommand(privateCmd)
	Cmd.AddCommand(publicCmd)
}
