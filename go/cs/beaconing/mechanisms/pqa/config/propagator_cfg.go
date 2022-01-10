package pqacfg

/* This file contains types and functions related to the propagation asepcts of the algorithm */

type PropagatorCfg map[InterfaceGroupIdentifier]InterfaceGroupCfg

type InterfaceGroupIdentifier string

type InterfaceGroupCfg struct {
	Interfaces                []uint16                   `yaml:"interfaces"`
	OptimizationTargetFilters []OptimizationTargetFilter `yaml:"optimization target filters"`
}

type InterfaceIdentifierCfg string
type PathQualityIdentifierCfg string

type OptimizationTargetFilter struct {
	Quality   PathQualityIdentifierCfg
	Direction OptimizationDirectionCfg
}

/*
func (cfg *PathQualityIdentifierCfg) PathQualityIdentifier() (pqa.PathQualityIdentifier, error) {
	switch pqa.PathQualityIdentifier(*cfg) {
	case pqa.QualityLatency:
		return pqa.QualityLatency, nil
	case pqa.QualityThroughput:
		return pqa.QualityThroughput, nil
	default:
		return "", serrors.New("Unknown Path quality identifier:", "identifier", cfg)
	}
}
/*

/*
func (name *InterfaceGroupIdentifier) InterfaceGroupIdentifier() pqa.InterfaceGroupIdentifier {
	return pqa.InterfaceGroupIdentifier(*name)
}
*/

func (cfg *PropagatorCfg) Validate() error {
	// TODO
	return nil
}
