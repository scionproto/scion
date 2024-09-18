// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

package iface

import (
	"strconv"
	"strings"
)

// IfIDType is the path-type-independent type for interface IDs. Interface IDs must fit in
// 64 bits. There is a lot of path-type-independent code that manipulates interface IDs without
// interpreting them. This type is a container for them.
type ID uint64

func (ifID ID) String() string {
	return strconv.FormatUint(uint64(ifID), 10)
}

// UnmarshalJSON unmarshals the JSON data into the IfID.
func (ifID *ID) UnmarshalJSON(data []byte) error {
	return ifID.UnmarshalText(data)
}

// UnmarshalText unmarshals the text into the IfID.
func (ifID *ID) UnmarshalText(text []byte) error {
	i, err := strconv.ParseUint(strings.ReplaceAll(string(text), "\"", ""), 10, 64)
	if err != nil {
		return err
	}
	*ifID = ID(i)
	return nil
}
