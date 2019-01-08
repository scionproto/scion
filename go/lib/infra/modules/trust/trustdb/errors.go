// Copyright 2018 ETH Anapaya Systems
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

package trustdb

import (
	"github.com/scionproto/scion/go/lib/common"
)

const (
	ErrCustKeyModified = "Cust key has been modified"
)

// IsCustKeyModifiedErr returns whether e is or contains ErrCustKeyModified.
func IsCustKeyModifiedErr(e error) bool {
	if common.GetErrorMsg(e) == ErrCustKeyModified {
		return true
	}
	if n := common.GetNestedError(e); n != nil {
		return IsCustKeyModifiedErr(n)
	}
	return false
}
