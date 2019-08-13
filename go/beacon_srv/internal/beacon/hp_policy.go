// Copyright 2019 ETH Zurich
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

package beacon

import (
	"encoding/json"
	"io/ioutil"
	"os"

	yaml "gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hiddenpath"
)

// HPGroup holds a HPGroup
type HPGroup struct {
	GroupCfgPath string `yaml:"CfgFilePath"`
	Group        hiddenpath.Group
}

// RegPolicy holds a segmentregistration policy
type RegPolicy struct {
	RegUp   bool `yaml:"RegUp"`
	RegDown bool `yaml:"RegDown"`
}

// HPPolicy holds the public and hidden registration policies for an interface
type HPPolicy struct {
	Public RegPolicy                        `yaml:"ps"`
	Hidden map[hiddenpath.GroupId]RegPolicy `yaml:"hps"`
}

// HPRegistration holds all the information required for hidden path segment registrations
type HPRegistration struct {
	HPGroups   map[hiddenpath.GroupId]*HPGroup `yaml:"hpGroups"`
	HPPolicies map[common.IFIDType]HPPolicy    `yaml:"segmentRegistration"`
}

// Validate verifies that all HPGroup configuration files exist
func (hp *HPRegistration) Validate() error {
	for _, g := range hp.HPGroups {
		if _, err := os.Stat(g.GroupCfgPath); err != nil {
			if os.IsNotExist(err) {
				return common.NewBasicError("HP group file does not exist", nil, "file", g.GroupCfgPath)
			}
		}
	}
	return nil
}

// ParseHPRegYaml parses the registration policies in yaml format and performs validation.
// Hidden path groups pointed to by config file paths are loaded.
func ParseHPRegYaml(b common.RawBytes) (*HPRegistration, error) {
	r := &HPRegistration{}
	if err := yaml.Unmarshal(b, r); err != nil {
		return nil, common.NewBasicError("Unable to parse policy", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if err := r.init(); err != nil {
		return nil, err
	}
	return r, nil
}

// LoadHPRegFromYaml loads the HPRegistration from a yaml file and performs validation.
// Hidden path groups pointed to by config file paths are loaded.
func LoadHPRegFromYaml(path string) (*HPRegistration, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, common.NewBasicError("Unable to read policy file", err, "path", path)
	}
	return ParseHPRegYaml(b)
}

func (hp *HPRegistration) init() error {
	for _, g := range hp.HPGroups {
		if err := g.loadGroup(); err != nil {
			return err
		}
	}
	return nil
}

func (g *HPGroup) loadGroup() error {
	b, err := ioutil.ReadFile(g.GroupCfgPath)
	if err != nil {
		return common.NewBasicError("Unable to read hidden path group file", err, "path", g.GroupCfgPath)
	}
	err = json.Unmarshal(b, &g.Group)
	if err != nil {
		return err
	}
	return nil
}
