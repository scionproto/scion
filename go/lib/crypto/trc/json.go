// Copyright 2018 ETH Zurich
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

package trc

import "github.com/scionproto/scion/go/lib/common"

const (
	InvalidNumFields     = "Invalid number of fields"
	MissingField         = "Missing json field"
	UnableValidateFields = "Unable to validate fields"
)

var trcFields = []string{certLogs, coreASes, creationTime, description,
	expirationTime, gracePeriod, isd, quarantine, quorumCAs, quorumTRC,
	rains, rootCAs, signatures, thresholdEEPKI, version}

var coreASFields = []string{"OfflineKey", "OfflineKeyAlg", "OnlineKey", "OnlineKeyAlg"}

func validateFields(m map[string]interface{}, fields []string) error {
	for _, field := range fields {
		if _, ok := m[field]; !ok {
			return common.NewBasicError(MissingField, nil, "field", field)
		}
	}
	if len(m) != len(fields) {
		return common.NewBasicError(InvalidNumFields, nil,
			"expected", len(fields), "actual", len(m))
	}
	return nil
}
