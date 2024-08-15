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

package key

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/file"
)

type symmetricKey []byte

// NewSymmetricCmd returns a cobra command that generates new symmetric keys.
func NewSymmetricCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		format string
		size   int
		force  bool
	}
	var cmd = &cobra.Command{
		Use:   "symmetric [flags] <symmetric-key-file>",
		Short: "Generate symmetric key at the specified location",
		Example: fmt.Sprintf(`  %[1]s symmetric master-0.key
  %[1]s symmetric --format base64 --size 512 master-0.key`, pather.CommandPath()),
		Long: `'symmetric' generates a symmetric key at the specified location.

The content is the symmetrics key in the specified format (base64 or pem with SYMMETRIC KEY block).
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			filename := args[0]
			if flags.size < 1 {
				return serrors.New("size must be a positive integer")
			}
			if err := file.CheckDirExists(filepath.Dir(filename)); err != nil {
				return serrors.Wrap("checking that directory of symmetric key exists", err)
			}
			key, err := generatesymmetricKey(flags.size)
			if err != nil {
				return serrors.Wrap("generating symmetric key", err)
			}
			raw, err := encodesymmetricKey(key, flags.format)
			if err != nil {
				return serrors.Wrap("encoding symmetric key", err)
			}
			if err := file.WriteFile(filename, raw, 0600, file.WithForce(flags.force)); err != nil {
				return serrors.Wrap("writing symmetric key", err)
			}
			fmt.Printf("Symmetric key successfully written to %q\n", filename)
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.format, "format", "pem",
		"The output format (pem|base64)",
	)
	cmd.Flags().IntVar(&flags.size, "size", 256,
		"The number of bits in the symmetric key",
	)
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"Force overwritting existing symmetric key",
	)
	return cmd
}

// generatesymmetricKey generates a new symmetric key.
func generatesymmetricKey(n int) (symmetricKey, error) {
	key := make(symmetricKey, n)
	_, err := rand.Read(key)
	return key, err
}

// encodesymmetricKey encodes the symmetric key in provided format (base64 or pem).
func encodesymmetricKey(key symmetricKey, format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "pem":
		return scrypto.EncodePEMSymmetricKey(key)
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(key)), nil
	default:
		return nil, serrors.New("unsupported format", "format", format)
	}
}
