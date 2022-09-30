// Copyright 2022 Anapaya Systems
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

package encoding

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// CheckEncodings checks if the specified format is supported.
func CheckEncodings(format string) error {
	switch strings.ToLower(format) {
	case "hex", "base64", "base64-url", "base64-raw", "base64-url-raw", "emoji":
		return nil
	default:
		return serrors.New("format not supported", "format", format)
	}
}

// EncodeBytes encodes the fingerprint in provided format:
// hex, base64, base64-url, base64-raw, base64-url-raw, emoji
func EncodeBytes(skid []byte, format string) (string, error) {
	switch strings.ToLower(format) {
	case "hex":
		return strings.ToLower(hex.EncodeToString(skid)), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(skid), nil
	case "base64-url":
		return base64.URLEncoding.EncodeToString(skid), nil
	case "base64-raw":
		return base64.RawStdEncoding.EncodeToString(skid), nil
	case "base64-url-raw":
		return base64.RawURLEncoding.EncodeToString(skid), nil
	case "emoji":
		return ToEmoji(skid), nil
	default:
		return "", serrors.New("unsupported format", "format", format)
	}
}
