// Copyright 2017 ETH Zurich
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

package integration

import (
	"os"

	yaml "gopkg.in/yaml.v2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// ASList is a list of ISD-AS identifiers grouped by core and non-core.
type ASList struct {
	Core    []addr.IA `yaml:"Core"`
	NonCore []addr.IA `yaml:"Non-core"`
}

// LoadASList parses the yaml file fileName and returns a structure with
// non-core and core ASes.
func LoadASList(fileName string) (*ASList, error) {
	buffer, err := os.ReadFile(fileName)
	if err != nil {
		return nil, serrors.Wrap("Unable to read from file", err, "name", fileName)
	}
	var asList ASList
	err = yaml.Unmarshal(buffer, &asList)
	if err != nil {
		return nil, serrors.Wrap("Unable to parse YAML data", err)
	}
	return &asList, nil
}

// AllASes returns all ASes in the ASList as a slice.
func (al *ASList) AllASes() []addr.IA {
	return append([]addr.IA(nil), append(al.Core, al.NonCore...)...)
}
