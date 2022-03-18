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
	"encoding/pem"
	"os"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// DecodeFromFile decodes a signed TRC from the provided file.
func DecodeFromFile(name string) (cppki.SignedTRC, error) {
	raw, err := os.ReadFile(name)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	block, _ := pem.Decode(raw)
	if block != nil && block.Type == "TRC" {
		raw = block.Bytes
	}
	return cppki.DecodeSignedTRC(raw)
}
