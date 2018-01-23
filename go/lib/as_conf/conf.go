// Copyright 2016 ETH Zurich
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

package as_conf

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
)

type ASConf struct {
	CertChainVersion int           `yaml:"CertChainVersion"`
	MasterASKey      util.B64Bytes `yaml:"MasterASKey"`
	PropagateTime    int           `yaml:"PropagateTime"`
	RegisterPath     bool          `yaml:"RegisterPath"`
	RegisterTime     int           `yaml:"RegisterTime"`
}

const CfgName = "as.yml"

const (
	ErrorOpen  = "Unable to open AS conf"
	ErrorParse = "Unable to parse AS conf"
)

var CurrConf *ASConf

func Load(path string) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return common.NewBasicError(ErrorOpen, err)
	}
	return Parse(b, path)
}

func Parse(data []byte, path string) error {
	c := &ASConf{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return common.NewBasicError(ErrorParse, err, "path", path)
	}
	CurrConf = c
	return nil
}

func (a ASConf) String() string {
	return fmt.Sprintf(
		"CertChainVersion:%d MasterASKey:%s PropagateTime:%d RegisterPath:%t RegisterTime:%d",
		a.CertChainVersion, a.MasterASKey, a.PropagateTime, a.RegisterPath, a.RegisterTime)
}
