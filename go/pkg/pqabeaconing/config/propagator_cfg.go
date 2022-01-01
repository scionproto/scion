/* This file contains types and functions related to the propagation asepcts of the algorithm */

package config

import (
	"io/ioutil"
	"log"

	pqa "github.com/scionproto/scion/go/pkg/pqabeaconing"

	yaml "gopkg.in/yaml.v2"
)

type PropagatorCfg map[InterfaceGroupIdentifier]InterfaceGroupCfg

type InterfaceGroupIdentifier string

type InterfaceGroupCfg struct {
	Interfaces                []IntfId                   `yaml:"interfaces"`
	OptimizationTargetFilters []OptimizationTargetFilter `yaml:"optimization target filters"`
}

type InterfaceIdentifierCfg string

type OptimizationTargetFilter struct {
	Quality   PathQualityIdentifierCfg
	Direction OptimizationDirectionCfg
}

func LoadPropagatorCfgYAML(file string) *PropagatorCfg {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	var cfg PropagatorCfg
	err = yaml.Unmarshal(data, &cfg)

	if err != nil {
		log.Fatal(err)
	}

	return &cfg

}

func (name *InterfaceGroupIdentifier) InterfaceGroupIdentifier() pqa.InterfaceGroupIdentifier {
	return pqa.InterfaceGroupIdentifier(*name)
}

func (pCfg *PropagatorCfg) Generate() (pqa.PropagationSettings, error) {
	set := pqa.PropagationSettings{}
	if err := pCfg.validate(); err != nil {
		return set, err
	}

	for ifaceGroupName, ifaceGroupCfg := range *pCfg {

		// Create map Interface group identifier -> list interfaces
		igrp := make(pqa.InterfaceGroup, 0)
		for _, ifaceIdentifier := range ifaceGroupCfg.Interfaces {
			igrp = append(igrp, ifaceIdentifier.Ifid())
		}

		igrpIdent := ifaceGroupName.InterfaceGroupIdentifier()
		set.IdentifierToInterfaceGroup = make(map[pqa.InterfaceGroupIdentifier]pqa.InterfaceGroup)
		set.QualityToDirectionToInterfaceGroups = make(map[pqa.PathQualityIdentifier]map[pqa.OptimizationDirection][]pqa.InterfaceGroupIdentifier)

		set.IdentifierToInterfaceGroup[igrpIdent] = igrp

		// Create map quality -> direction -> interface group identifier
		for _, oFilter := range ifaceGroupCfg.OptimizationTargetFilters {
			quality := oFilter.Quality.PathQualityIdentifier()
			var directions []pqa.OptimizationDirection
			if oFilter.Direction != "" {
				directions = []pqa.OptimizationDirection{oFilter.Direction.OptimizationDirection()}
			} else {
				directions = []pqa.OptimizationDirection{pqa.OptimizationDirectionForward, pqa.OptimizationDirectionBackward}
			}

			for _, direction := range directions {
				if _, ok := set.QualityToDirectionToInterfaceGroups[quality]; !ok {
					set.QualityToDirectionToInterfaceGroups[quality] = make(map[pqa.OptimizationDirection][]pqa.InterfaceGroupIdentifier)
				}
				if _, ok := set.QualityToDirectionToInterfaceGroups[quality][direction]; !ok {
					set.QualityToDirectionToInterfaceGroups[quality][direction] = make([]pqa.InterfaceGroupIdentifier, 0)
				}
				set.QualityToDirectionToInterfaceGroups[quality][direction] = append(set.QualityToDirectionToInterfaceGroups[quality][direction], igrpIdent)
			}
		}

	}

	return set, nil
}

func (cfg *PropagatorCfg) validate() error {
	return nil
}
