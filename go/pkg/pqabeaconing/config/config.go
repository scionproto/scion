package config

import (
	pqa "github.com/scionproto/scion/go/pkg/pqabeaconing"
)

type IntfId string

type ConfigPaths struct {
	Static     string
	Originator string
	Propagator string
}

func DefaultConfigPaths() ConfigPaths {
	return ConfigPaths{
		Static:     "testcfgs/static/config.yml",
		Originator: "testcfgs/static/config.yml",
		Propagator: "testcfgs/propagator/config.yml",
	}
}

type PqaCfg struct {
	StaticCfg     StaticCfg
	OriginatorCfg OriginatorCfg
	PropagatorCfg PropagatorCfg
}

func (paths *ConfigPaths) LoadConfigFiles() *PqaCfg {
	var cfg PqaCfg

	cfg.StaticCfg = *LoadStaticCfgYAML(paths.Static)
	cfg.OriginatorCfg = *LoadOriginatorCfgYAML(paths.Originator)
	cfg.PropagatorCfg = *LoadPropagatorCfgYAML(paths.Propagator)

	return &cfg
}

func (pqaCfg *PqaCfg) Generate() (*pqa.Extension, error) {
	ext := pqa.Extension{}
	var err error

	ext.StaticSettings, err = pqaCfg.StaticCfg.Generate()
	for err != nil {
		return nil, err
	}

	ext.OriginationSettings, err = pqaCfg.OriginatorCfg.Generate()
	for err != nil {
		return nil, err
	}

	ext.PropagationSettings, err = pqaCfg.PropagatorCfg.Generate()
	for err != nil {
		return nil, err
	}

	return &ext, nil
}

func (ident *IntfId) Ifid() pqa.Ifid {
	return pqa.Ifid(*ident)
}
