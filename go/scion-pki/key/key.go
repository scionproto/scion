// Copyright 2021 Anapaya Systems
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

// Package key defines cobra commands to manage private and public keys.
package key

import (
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/pkg/command"
)

// Cmd creates a new cobra command to manage keys
func Cmd(pather command.Pather) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "key",
		Short: "Manage private and public keys",
	}
	joined := command.Join(pather, cmd)

	cmd.AddCommand(
		NewKeyPrivateCmd(joined),
		NewKeyPublicCmd(joined),
	)

	return cmd

}
