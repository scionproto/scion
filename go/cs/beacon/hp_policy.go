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

	yaml "gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/util"
)

// HPGroup holds a hidden path group
type HPGroup struct {
	GroupCfgPath string `yaml:"CfgFilePath"`
	Group        hiddenpath.Group
}

// RegPolicy holds a segmentregistration policy
type RegPolicy struct {
	RegUp         bool         `yaml:"RegUp"`
	RegDown       bool         `yaml:"RegDown"`
	MaxExpiration util.DurWrap `yaml:"MaxExpiration"`
}

// HPPolicy holds the public and hidden registration policies for an interface
type HPPolicy struct {
	Public RegPolicy                        `yaml:"PS"`
	Hidden map[hiddenpath.GroupId]RegPolicy `yaml:"HPS"`
}

// HPPolicies holds all the hidden path registration policies for a BS
type HPPolicies struct {
	DefaultAction   string                       `yaml:"DefaultAction"`
	HiddenAndPublic bool                         `yaml:"HiddenAndPublic"`
	Policies        map[common.IFIDType]HPPolicy `yaml:"Policies"`
}

// HPRegistration holds all the information required for hidden path segment registrations
type HPRegistration struct {
	HPPolicies HPPolicies                      `yaml:"SegmentRegistration"`
	HPGroups   map[hiddenpath.GroupId]*HPGroup `yaml:"HPGroups"`
}

// Validate verifies that for all hidden path policies the referenced Group exists
// and checks if all GroupId keys match the initialized HPGroup
func (hp *HPRegistration) Validate() error {
	for _, p := range hp.HPPolicies.Policies {
		for id := range p.Hidden {
			if _, ok := hp.HPGroups[id]; !ok {
				return common.NewBasicError("Policy references unavailable Group",
					nil, "GroupId", id)
			}
		}
	}
	for id, g := range hp.HPGroups {
		if id != g.Group.Id {
			return common.NewBasicError("GroupId key doesn't match loaded HPGroup",
				nil, "key", id, "loaded", g.Group.Id)
		}
	}
	return nil
}

// ParseHPRegYaml parses the registration policies in yaml format and performs validation.
// Hidden path groups pointed to by config file paths are loaded.
func ParseHPRegYaml(b common.RawBytes) (*HPRegistration, error) {
	r := &HPRegistration{}
	if err := yaml.UnmarshalStrict(b, r); err != nil {
		return nil, common.NewBasicError("Unable to parse policy", err)
	}
	if err := r.init(); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
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
		return common.NewBasicError("Unable to read hidden path group file", err,
			"path", g.GroupCfgPath)
	}
	err = json.Unmarshal(b, &g.Group)
	if err != nil {
		return err
	}
	return nil
}
