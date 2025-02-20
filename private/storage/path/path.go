// Copyright 2021 ETH Zurich, Anapaya Systems
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

package path

import (
	"strconv"
	"strings"

	seg "github.com/scionproto/scion/pkg/segment"
)

type GroupIDs []uint64

func (g *GroupIDs) Scan(src any) error {
	var group string
	switch src := src.(type) {
	case string:
		group = src
	case []byte:
		group = string(src)
	}
	idStrings := strings.Split(group, ",")
	res := make([]uint64, len(idStrings))
	for i, is := range idStrings {
		id, err := strconv.ParseInt(is, 10, 64)
		if err != nil {
			return err
		}
		res[i] = uint64(id)
	}
	*g = GroupIDs(res)
	return nil
}

type SegTypes []seg.Type

func (t *SegTypes) Scan(src any) error {
	var group string
	switch src := src.(type) {
	case string:
		group = src
	case []byte:
		group = string(src)
	}
	typeStrings := strings.Split(group, ",")
	res := make([]seg.Type, len(typeStrings))
	for i, ts := range typeStrings {
		t, err := strconv.Atoi(ts)
		if err != nil {
			return err
		}
		res[i] = seg.Type(t)
	}
	*t = SegTypes(res)
	return nil
}
