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
	"io/ioutil"

	log "github.com/Sirupsen/logrus"
	"github.com/netsec-ethz/scion/go/lib/util"
	"gopkg.in/yaml.v2"
)

type ASConf struct {
	CertChainVersion int           `yaml:"CertChainVersion"`
	MasterASKey      util.B64Bytes `yaml:"MasterASKey"`
	PropagateTime    int           `yaml:"PropagateTime"`
	RegisterPath     bool          `yaml:"RegisterPath"`
	RegisterTime     int           `yaml:"RegisterTime"`
}

var CurrConf *ASConf

func Load(path string) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Unable to open AS conf")
		return err
	}
	if err = Parse(b); err != nil {
		return err
	}
	log.WithField("path", path).Info("Loaded AS conf")
	return nil
}

func Parse(data []byte) error {
	c := &ASConf{}
	if err := yaml.Unmarshal(data, c); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Unable to parse AS conf")
		return err
	}
	CurrConf = c
	return nil
}
