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
	"fmt"

	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "keys",
	Short: "Generate keys for the SCION control plane PKI.",
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
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runGenKey(args)
	},
}

var cleanKeysCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove all the keys [NOT IMPLEMENTED]",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("clean sub command is not implemented")
	},
}

func init() {
	Cmd.AddCommand(genCmd)
	Cmd.AddCommand(cleanKeysCmd)
}
