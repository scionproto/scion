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

package certs

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

// Dir returns the directory where certificates are written to.
func Dir(dir string, ia addr.IA) string {
	return filepath.Join(pkicmn.GetAsPath(dir, ia), pkicmn.CertsDir)
}

// IssuerFile returns the file path for the issuer certificate.
func IssuerFile(dir string, ia addr.IA, ver scrypto.Version) string {
	return filepath.Join(Dir(dir, ia), fmt.Sprintf(pkicmn.IssuerNameFmt, ia.I, ia.A.FileFmt(), ver))
}

// ASFile returns the file path for the certificate chain.
func ASFile(dir string, ia addr.IA, ver scrypto.Version) string {
	return filepath.Join(Dir(dir, ia), fmt.Sprintf(pkicmn.CertNameFmt, ia.I, ia.A.FileFmt(), ver))
}

// translateKeys translates the keys to certificate key metadata.
func translateKeys(keys map[cert.KeyType]keyconf.Key) map[cert.KeyType]scrypto.KeyMeta {
	m := make(map[cert.KeyType]scrypto.KeyMeta)
	for keyType, key := range keys {
		m[keyType] = scrypto.KeyMeta{
			Algorithm:  key.Algorithm,
			Key:        append([]byte{}, key.Bytes...),
			KeyVersion: key.Version,
		}
	}
	return m
}

// MatchFiles matches all issuer certificate and certificate chain file names.
func MatchFiles(files []string) ([]string, []string) {
	var issuers, chains []string
	for _, file := range files {
		_, name := filepath.Split(file)
		switch {
		case match(pkicmn.IssuerNameFmt, name):
			issuers = append(issuers, file)
		case match(pkicmn.CertNameFmt, name):
			chains = append(chains, file)
		default:
			pkicmn.QuietPrint("Skipping non-certificate file: %s\n", file)
		}
	}
	return issuers, chains
}

func match(fmtString, name string) bool {
	matched, _ := filepath.Match(strings.NewReplacer("%d", "*", "%s", "*").Replace(fmtString), name)
	return matched
}
