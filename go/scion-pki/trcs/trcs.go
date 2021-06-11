// Copyright 2020 Anapaya Systems
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

	"github.com/scionproto/scion/go/pkg/command"
)

func Cmd(pather command.Pather) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "trc",
		Aliases: []string{"trcs"},
		Short:   "Manage TRCs for the SCION control plane PKI",
	}
	joined := command.Join(pather, cmd)
	cmd.AddCommand(
		newCombine(joined),
		newHuman(joined),
		newFormatCmd(joined),
		newExtract(joined),
		newPayload(joined),
		newVerify(joined),
		newSign(joined),
	)
	return cmd
}

func addOutputFlag(flag *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(flag, "out", "o", "", "Output file (required)")
	cmd.MarkFlagRequired("out")
}
