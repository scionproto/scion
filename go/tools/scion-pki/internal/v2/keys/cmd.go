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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var Cmd = &cobra.Command{
	Use:   "keys",
	Short: "Generate keys for the SCION control plane PKI. [DEPRECATED]",
	Long: `
'keys' can be used to generate all the necessary keys used in the SCION control plane PKI as well
as the AS master key.

Selector:
	*-*
		All ISDs and ASes under the root directory.
	X-*
		All ASes in ISD X.
	X-Y
		A specific AS X-Y, e.g. AS 1-ff00:0:300
`,
}

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate new keys",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runGenKey(args[0]); err != nil {
			return common.NewBasicError("unable to generate keys", err)
		}
		return nil
	},
}

var privateCmd = &cobra.Command{
	Use:   "private",
	Short: "Generate private keys",
	Args:  cobra.ExactArgs(1),
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
	Args:  cobra.ExactArgs(1),
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
	Cmd.AddCommand(genCmd)
}
