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

package keys

import (
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

// PrivateDir returns the directory where the private keys are written to.
func PrivateDir(out string, ia addr.IA) string {
	return filepath.Join(pkicmn.GetAsPath(out, ia), "keys")
}

// PrivateFile returns the file where the private key is written to.
func PrivateFile(out string, id keyconf.ID) string {
	return filepath.Join(PrivateDir(out, id.IA), keyconf.PrivateKeyFile(id.Usage, id.Version))
}

// PublicDir returns the directory where the public keys are written to.
func PublicDir(out string, ia addr.IA) string {
	return filepath.Join(pkicmn.GetAsPath(out, ia), "pub")
}

// PublicFile returns the file where the public key is written to.
func PublicFile(out string, id keyconf.ID) string {
	return filepath.Join(PublicDir(out, id.IA),
		keyconf.PublicKeyFile(id.Usage, id.IA, id.Version))
}
