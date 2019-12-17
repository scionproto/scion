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

package keyconf

import (
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// LoadingRing loads the private keys on-demand from the file system.
type LoadingRing struct {
	Dir string
	IA  addr.IA
}

// PrivateKey returns the private key for the given usage and version. If it
// is not in the key ring, an error is returned.
func (r LoadingRing) PrivateKey(usage Usage, version scrypto.KeyVersion) (Key, error) {
	id := ID{
		IA:      r.IA,
		Usage:   usage,
		Version: version,
	}
	file := filepath.Join(r.Dir, PrivateKeyFile(usage, version))
	return LoadKeyFromFile(file, PrivateKey, id)
}
