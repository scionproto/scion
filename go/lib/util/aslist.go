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
	"github.com/netsec-ethz/scion/go/lib/common"
)

type asData struct {
	Core    []string `yaml:"Core"`
	NonCore []string `yaml:"Non-core"`
}

type ASList struct {
	Core    []*addr.ISD_AS
	NonCore []*addr.ISD_AS
}

// LoadASList parses the yaml file fileName and returns a structure with
// non-core and core ASes.
func LoadASList(fileName string) (*ASList, error) {
	asList := &ASList{}

	buffer, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, common.NewError("Unable to read from file", "name", fileName, "err", err)
	}

	var locations asData
	err = yaml.Unmarshal(buffer, &locations)
	if err != nil {
		return nil, common.NewError("Unable to parse YAML data", "err", err)
	}

	asList.Core, err = parse(locations.Core)
	if err != nil {
		return nil, err
	}
	asList.NonCore, err = parse(locations.NonCore)
	if err != nil {
		return nil, err
	}
	return asList, nil
}

func parse(names []string) ([]*addr.ISD_AS, error) {
	var iaList []*addr.ISD_AS
	for _, name := range names {
		ia, err := addr.IAFromString(name)
		if err != nil {
			return nil, common.NewError("Unable to parse AS Name", "ISDAS", name, "err", err)
		}
		iaList = append(iaList, ia)
	}
	return iaList, nil
}
