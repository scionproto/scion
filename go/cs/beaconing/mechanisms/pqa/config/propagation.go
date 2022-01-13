package pqacfg

/* This file contains types and functions related to the propagation asepcts of the algorithm */

type PropagatorCfg map[InterfaceGroupIdentifier]InterfaceGroupCfg

type InterfaceGroupIdentifier string

type InterfaceGroupCfg struct {
	Interfaces                []uint16                   `yaml:"interfaces"`
	OptimizationTargetFilters []OptimizationTargetFilter `yaml:"optimization target filters"`
}

type OptimizationTargetFilter struct {
	Quality   QualityIdentifier
	Direction DirectionIdentifier
}
