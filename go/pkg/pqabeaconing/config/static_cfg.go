/* This file contains types and functions related to configuration that ASs are not intended to modify */

package config

import (
	"errors"
	"io/ioutil"
	"log"

	pqa "github.com/scionproto/scion/go/pkg/pqabeaconing"

	yaml "gopkg.in/yaml.v2"
)

type StaticCfg struct {
	// The maximum number of paths to be considered for each optimization target
	BeaconsPerOPtimizationQuality int `yaml:"beacons per quality"`
	// Possible path qualities
	PathQualities map[PathQualityIdentifierCfg]PathQualityCfg `yaml:"path qualities"`
}

type PathQualityCfg struct {
	Combination       CombinationIdentifierCfg `yaml:"combination"`
	Optimality        OptimalityIdentifierCfg  `yaml:"optimality"`
	SymmetryTolerance float64                  `yaml:"symmetry tolerance"`
}

type PathQualityIdentifierCfg string

func (intf *PathQualityIdentifierCfg) PathQualityIdentifier() pqa.PathQualityIdentifier {
	return pqa.PathQualityIdentifier(*intf)
}

type CombinationIdentifierCfg string

func (ctCfg *CombinationIdentifierCfg) CombinationType() pqa.CombinationType {
	return pqa.CombinationType(*ctCfg)
}

type OptimalityIdentifierCfg string

func (otCfg *OptimalityIdentifierCfg) OptimalityType() pqa.OptimalityType {
	return pqa.OptimalityType(*otCfg)
}

func LoadStaticCfgYAML(file string) *StaticCfg {
	yfile, err := ioutil.ReadFile(file)

	if err != nil {
		log.Fatal(err)
	}

	var data StaticCfg
	data.PathQualities = make(map[PathQualityIdentifierCfg]PathQualityCfg)

	err2 := yaml.Unmarshal(yfile, &data)

	if err2 != nil {
		log.Fatal(err)
	}

	return &data
}

// Generates a pqa.StaticSettings given a cfg.StaticCfg
func (cfg *StaticCfg) Generate() (pqa.StaticSettings, error) {
	set := pqa.StaticSettings{}
	if err := cfg.Validate(); err != nil {
		return set, err
	}

	set.PathQualities = make(map[pqa.PathQualityIdentifier]pqa.PathQuality)

	for pqIntfCfg, pq := range cfg.PathQualities {
		set.PathQualities[pqIntfCfg.PathQualityIdentifier()] = pqa.PathQuality{
			CombinationType:   pq.Combination.CombinationType(),
			OptimalityType:    pq.Optimality.OptimalityType(),
			SymmetryTolerance: pq.SymmetryTolerance,
		}
	}

	return set, nil
}

func (cfg *StaticCfg) Validate() error {
	if cfg.BeaconsPerOPtimizationQuality < 1 {
		return errors.New("missing or invalid value for beacons per optimization quality")
	}

	for _, pq := range cfg.PathQualities {
		if err := pq.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (pq *PathQualityCfg) Validate() error {
	if pq.Combination == "" {
		return errors.New("missing or invalid value for combination")
	}

	if pq.Optimality == "" {
		return errors.New("missing or invalid value for optimality")
	}

	if pq.SymmetryTolerance <= 0 {
		return errors.New("missing or invalid value for symmetry tolerance")
	}

	return nil
}
