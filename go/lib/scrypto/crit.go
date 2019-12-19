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

package scrypto

import (
	"encoding/json"

	"github.com/scionproto/scion/go/lib/serrors"
)

// ErrInvalidCrit indicates that the value for the crit key is invalid.
var ErrInvalidCrit = serrors.New("invalid crit")

// CheckCrit checks that b is a JSON list and contains exactly the entries in
// critFields.
func CheckCrit(b []byte, critFields []string) error {
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	if len(list) != len(critFields) {
		return serrors.WithCtx(ErrInvalidCrit, "len", len(list))
	}
	for i, expected := range critFields {
		if list[i] != expected {
			return serrors.WithCtx(ErrInvalidCrit, "idx", i,
				"expected", expected, "actual", list[i])
		}
	}
	return nil
}
