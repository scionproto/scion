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

package cert

import (
	"encoding/json"
	"errors"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	// InvalidCrit indicates that the value for the crit key is invalid.
	InvalidCrit = "invalid crit"
	// InvalidSignatureType indicates an invalid signature type.
	InvalidSignatureType = "invalid signature type"
)

var (
	// ErrCritNotSet indicates that crit is not set.
	ErrCritNotSet = errors.New("crit not set")
	// ErrNotUTF8 indicates an invalid encoding.
	ErrNotUTF8 = errors.New("not utf-8 encoded")
	// ErrSignatureTypeNotSet indicates the signature type is not set.
	ErrSignatureTypeNotSet = errors.New("signature type not set")
)

func checkCrit(b []byte, critFields []string) error {
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	if len(list) != len(critFields) {
		return common.NewBasicError(InvalidCrit, nil, "len", len(list))
	}
	for i, expected := range critFields {
		if list[i] != expected {
			return common.NewBasicError(InvalidCrit, nil, "idx", i,
				"expected", expected, "actual", list[i])
		}
	}
	return nil
}
