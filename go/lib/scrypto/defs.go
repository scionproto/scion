// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"encoding/base64"

	"github.com/scionproto/scion/go/lib/common"
)

// Base64 is the base64 encoding used when packing and unpacking encoded data.
// In accordance with rfc7515 (see https://tools.ietf.org/html/rfc7515#section-2),
// this is the URL safe encoding with padding omitted.
var Base64 = base64.RawURLEncoding

// JWSignatureInput computes the signature input according to rfc7517 (see:
// https://tools.ietf.org/html/rfc7515#section-5.1)
func JWSignatureInput(protected string, payload string) common.RawBytes {
	input := make([]byte, len(protected)+len(payload)+1)
	copy(input[:len(protected)], protected)
	input[len(protected)] = '.'
	copy(input[len(protected)+1:], payload)
	return input
}

// JWSignature uses the encoding in accordance with rfc7515 when packing and
// unpacking signatures.
type JWSignature []byte

// UnmarshalText parses the base64url encoded bytes.
func (s *JWSignature) UnmarshalText(b []byte) error {
	buf := make([]byte, Base64.DecodedLen(len(b)))
	n, err := Base64.Decode(buf, b)
	if err != nil {
		return err
	}
	*s = buf[:n]
	return nil
}

// MarshalText returns the base64url encoded bytes
func (s JWSignature) MarshalText() ([]byte, error) {
	b := make([]byte, Base64.EncodedLen(len(s)))
	Base64.Encode(b, s)
	return b, nil
}
