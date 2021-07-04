// Copyright 2016 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

package addr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostFromRaw(t *testing.T) {
	var testSlice = []byte{}
	var hostAddrTypes = []struct {
		name     string
		addrType HostAddrType
	}{
		{"HostTypeIPv4", HostTypeIPv4},
		{"HostTypeIPv6", HostTypeIPv6},
		{"HostTypeSVC", HostTypeSVC},
	}

	t.Log("HostFromRaw should return a non-nil error when the length of the slice argument is less than expected")

	for _, addrType := range hostAddrTypes {
		t.Run(addrType.name, func(t *testing.T) {
			_, err := HostFromRaw(testSlice, addrType.addrType)
			assert.Error(t, err, "Must return non-nil error")
		})
	}
}
