package pqacfg

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

type IntfId string

type PqaCfg struct {
	Origination OriginatorCfg `yaml:"originator"`
	Propagation PropagatorCfg `yaml:"propagator"`
}

func LoadPqaCfgFromYAML(file string) (*PqaCfg, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var cfg PqaCfg
	err = yaml.Unmarshal(data, &cfg)

	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
