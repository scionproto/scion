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

package testcrypto

import (
	"io"
	"time"
)

// Options configures a [Run] of the test crypto generator.
type Options struct {
	// TopoFile is the path to the topology description file.
	TopoFile string
	// OutDir is the output directory for the generated crypto material.
	OutDir string
	// NoCleanup keeps the intermediate template files.
	NoCleanup bool
	// ISDDir groups ASes under per-ISD directories.
	ISDDir bool
	// ASValidity is the validity period of generated AS certificates. If zero,
	// it defaults to 3 days.
	ASValidity time.Duration
	// Writer receives progress output. If nil, output is discarded.
	Writer io.Writer
}

// Run generates the crypto material (keys, certificates, TRCs) for a test
// topology. It is the library entry point used by tools that embed crypto
// generation in process, equivalent to the `scion-pki testcrypto` command.
func Run(opts Options) error {
	validity := opts.ASValidity
	if validity == 0 {
		validity = 3 * 24 * time.Hour
	}
	w := opts.Writer
	if w == nil {
		w = io.Discard
	}
	return testcrypto(opts.TopoFile, opts.OutDir, opts.NoCleanup, opts.ISDDir, validity, w)
}
