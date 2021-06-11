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

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/env"
)

func newVersion() *cobra.Command {
	major, minor, patch := 0, 5, 0
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show the scion-pki version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(env.VersionInfo())
			fmt.Printf("  PKI version:   v%d.%d.%d\n", major, minor, patch)
		},
	}
	return cmd
}
