// Copyright 2026 Anapaya Systems
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

// Package out defines the output directory layout of testgen. The AS directory
// naming matches scion-pki testcrypto so generated crypto material lands in the
// same per-AS directories.
package out

import (
	"os"
	"path/filepath"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Dir is the output directory rooted at a base path.
type Dir struct {
	base string
	isd  bool
}

// New returns a Dir rooted at base. If isd is true, AS directories are grouped
// under per-ISD directories (matching testcrypto's --isd-dir).
func New(base string, isd bool) Dir {
	return Dir{base: base, isd: isd}
}

// Base returns the root output directory.
func (d Dir) Base() string { return d.base }

// NetworkAllocations returns the path of the network allocations file.
func (d Dir) NetworkAllocations() string {
	return filepath.Join(d.base, "network-allocations.yml")
}

// Clab returns the path of the containerlab topology file for the given lab.
func (d Dir) Clab(labName string) string {
	return filepath.Join(d.base, labName+".clab.yml")
}

// Instructions returns the path of the run instructions file.
func (d Dir) Instructions() string { return filepath.Join(d.base, "INSTRUCTIONS.md") }

// AS returns the per-AS directory, matching testcrypto's layout.
func (d Dir) AS(ia addr.IA) string {
	if d.isd {
		return filepath.Join(
			d.base,
			addr.FormatISD(ia.ISD(), addr.WithDefaultPrefix()),
			addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator()),
		)
	}
	return filepath.Join(
		d.base,
		addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator()),
	)
}

// Host returns the per-host directory under the AS directory.
func (d Dir) Host(ia addr.IA, host string) string {
	return filepath.Join(d.AS(ia), host)
}

// WriteFile creates the parent directories and writes the file.
func WriteFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return serrors.Wrap("creating directory", err, "dir", filepath.Dir(path))
	}
	if err := os.WriteFile(path, content, 0644); err != nil {
		return serrors.Wrap("writing file", err, "path", path)
	}
	return nil
}
