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

package scrypto

import (
	"bytes"
	"encoding/pem"

	"github.com/scionproto/scion/go/lib/serrors"
)

// ParsePEMSymmetricKey parses the first PEM block in b and returns the data within.
//
// This provides a more idiomatic way of accessing errors (when compared with the
// pem.Decode function), and allows us to add more validation in the future (e.g.,
// if we want to make use of PEM headers).
func ParsePEMSymmetricKey(b []byte) ([]byte, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, serrors.New("parse error")
	}
	if len(block.Bytes) == 0 {
		return nil, serrors.New("key not found")
	}
	return block.Bytes, nil
}

// EncodePEMSymmetricKey encodes the raw key in a PEM block with the SYMMETRIC KEY
// type.
func EncodePEMSymmetricKey(key []byte) ([]byte, error) {
	block := &pem.Block{
		Type:  "SYMMETRIC KEY",
		Bytes: key,
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
