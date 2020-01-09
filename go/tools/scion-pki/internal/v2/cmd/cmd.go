// Copyright 2019 Anapaya Systems
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

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/certs"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/keys"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/tmpl"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/trcs"
)

var Cmd = &cobra.Command{
	Use:   "v2",
	Short: "Scion Public Key Infrastructure Management Tool",
	Long: `scion-pki is a tool to generate keys, certificates, and trust
root configuration files used in the SCION control plane PKI.

The subcommands expect the contents of the root directory to follow a rigid and
predefined file structure:

<root>
├── ISD1
│   ├── ASff00_0_c
│   │   ├── as-v1.toml      # AS certificate configuration (versioned)
│   │   ├── certs           # Dir containing issuer certificates and certificate chains
│   │   ├── issuer-v1.toml  # Issuer certificate configuration (versioned)
│   │   ├── keys            # Dir containing private keys
│   │   ├── keys.toml       # Keys configuration file
│   │   └── pub             # Dir containing public keys
│   ├── trcs                # Dir containing partial and signed TRCs
│   │   └── ISD1-V1.parts   # Dir containing partially signed TRC for specific version
│   └── trc-v1.toml         # TRC configuration (versioned)

A sample file structure can be generated in 'DIR' by running:
  scion-pki v2 tmpl sample > $DIR/sample.topo
  scion-pki v2 tmpl topo -d $DIR sample.topo

The 'certs', 'keys', 'trcs' directories are created on demand by the tool.
`,
}

func init() {
	Cmd.AddCommand(certs.Cmd)
	Cmd.AddCommand(tmpl.Cmd)
	Cmd.AddCommand(keys.Cmd)
	Cmd.AddCommand(trcs.Cmd)
}
