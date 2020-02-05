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

package common

import (
	"reflect"
	"strconv"
	"strings"
)

const (
	// LineLen is the number of bytes that all SCION headers are padded to a multiple of.
	LineLen     = 8
	MinMTU      = 1280
	MaxMTU      = (1 << 16) - 1
	TimeFmt     = "2006-01-02 15:04:05.000000-0700"
	TimeFmtSecs = "2006-01-02 15:04:05-0700"
)

const (
	BR  = "BR"
	CS  = "CS"
	SB  = "SB"
	RS  = "RS"
	SIG = "SIG"

	CPService = "Control Plane Service"
)

// IFIDType is the type for interface IDs.
type IFIDType uint64

func (ifid IFIDType) String() string {
	return strconv.FormatUint(uint64(ifid), 10)
}

// UnmarshalJSON unmarshals the JSON data into the IfID.
func (ifid *IFIDType) UnmarshalJSON(data []byte) error {
	return ifid.UnmarshalText(data)
}

// UnmarshalText unmarshals the text into the IfID.
func (ifid *IFIDType) UnmarshalText(text []byte) error {
	i, err := strconv.ParseUint(strings.ReplaceAll(string(text), "\"", ""), 10, 64)
	if err != nil {
		return err
	}
	*ifid = IFIDType(i)
	return nil
}

const IFIDBytes = 8

func TypeOf(v interface{}) string {
	t := reflect.TypeOf(v)
	if t != nil {
		return t.String()
	}
	return "<nil>"
}
