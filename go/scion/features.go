// Copyright 2020 Anapaya Systems
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

package main

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/serrors"
)

type features struct {
	HeaderV2 bool
}

func parseFeatures(input []string) (features, error) {
	var f features
	m := f.mapping()
	for _, key := range input {
		val, ok := m[key]
		if !ok {
			return features{}, serrors.New("feature not supported", "feature", key)
		}
		*val = true
	}
	return f, nil
}

func (f *features) mapping() map[string]*bool {
	return map[string]*bool{
		"header_v2": &f.HeaderV2,
	}
}

func (f features) supported() string {
	var s []string
	for k := range f.mapping() {
		s = append(s, k)
	}
	return fmt.Sprintf("(%s)", strings.Join(s, "|"))
}
