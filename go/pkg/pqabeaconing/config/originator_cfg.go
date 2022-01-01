/* This file contains types and functions related to the origination aspects of the algorithm */

package config

import (
	"errors"
	"io/ioutil"
	"log"

	pqa "github.com/scionproto/scion/go/pkg/pqabeaconing"

	yaml "gopkg.in/yaml.v2"
)

type OriginatorCfg struct {
	OptimizationTargets map[OptimizationTargetIdentifierCfg]OptimizationTargetCfg `yaml:"optimization targets"`
	OriginationCfgs     map[IntfId]OriginationCfg                                 `yaml:"origination configuration"`
}

type OptimizationTargetCfg struct {
	Quality    PathQualityIdentifierCfg `yaml:"quality"`
	Direction  OptimizationDirectionCfg `yaml:"direction"`
	Uniquifier uint8                    `yaml:"uniquifier"`
}

type OriginationCfg [][]OptimizationTargetIdentifierCfg

type OptimizationTargetIdentifierCfg string

func (otIdentCfg *OptimizationTargetIdentifierCfg) OptimizationTargetIdentifier() pqa.OptimizationTargetIdentifier {
	return pqa.OptimizationTargetIdentifier(*otIdentCfg)
}

type OptimizationDirectionCfg string

func (odCfg *OptimizationDirectionCfg) OptimizationDirection() pqa.OptimizationDirection {
	return pqa.OptimizationDirection(*odCfg)
}

func LoadOriginatorCfgYAML(file string) *OriginatorCfg {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	var cfg OriginatorCfg
	err = yaml.Unmarshal(data, &cfg)

	if err != nil {
		log.Fatal(err)
	}

	return &cfg
}

func (cfg *OriginatorCfg) Generate() (pqa.OriginationSettings, error) {
	set := pqa.OriginationSettings{}

	if err := cfg.validate(); err != nil {
		return set, err
	}

	set.OptimizationTargets = make(map[pqa.OptimizationTargetIdentifier]pqa.OptimizationTarget)
	set.OriginationOrder = make(map[pqa.Ifid][][]pqa.OptimizationTargetIdentifier, 0)

	for ident, otCfg := range cfg.OptimizationTargets {
		set.OptimizationTargets[ident.OptimizationTargetIdentifier()] = pqa.OptimizationTarget{
			Quality:    otCfg.Quality.PathQualityIdentifier(),
			Direction:  otCfg.Direction.OptimizationDirection(),
			Uniquifier: otCfg.Uniquifier,
		}
	}

	for intfId, origCfg := range cfg.OriginationCfgs {
		intfOrigOrder := make([][]pqa.OptimizationTargetIdentifier, 0)
		for _, origIntervalCfg := range origCfg {

			origInterval := make([]pqa.OptimizationTargetIdentifier, 0)
			for _, optimTarget := range origIntervalCfg {
				origInterval = append(origInterval, optimTarget.OptimizationTargetIdentifier())
			}
			intfOrigOrder = append(intfOrigOrder, (origInterval))
		}
		set.OriginationOrder[pqa.Ifid(intfId)] = intfOrigOrder
	}

	return set, nil
}

func (cfg *OriginatorCfg) validate() error {
	for _, targetCfg := range cfg.OptimizationTargets {
		if err := targetCfg.validate(); err != nil {
			return err
		}
	}

	return nil
}

func (cfg *OptimizationTargetCfg) validate() error {
	if cfg.Quality == "" {
		return errors.New("missing quality")
	}

	if cfg.Direction == "" {
		return errors.New("missing direction")
	}

	return nil

}
