// Copyright 2017 ETH Zurich
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

package util

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"

	"github.com/netsec-ethz/scion/go/lib/addr"
)

type asData struct {
	Core    []string `yaml:"Core"`
	NonCore []string `yaml:"Non-core"`
}

// LoadASList parses the yaml file fileName and returns a slice containing the
// ASes within
func LoadASList(fileName string) ([]*addr.ISD_AS, error) {
	list := make([]*addr.ISD_AS, 0)

	buffer, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	var locations asData
	yaml.Unmarshal(buffer, &locations)

	for _, isdas := range locations.Core {
		as, err := addr.IAFromString(isdas)
		if err != nil {
			return nil, err
		}
		list = append(list, as)
	}

	for _, isdas := range locations.NonCore {
		as, err := addr.IAFromString(isdas)
		if err != nil {
			return nil, err
		}
		list = append(list, as)
	}
	return list, nil
}
