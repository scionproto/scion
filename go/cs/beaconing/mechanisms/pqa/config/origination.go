/* This file contains types and functions related to the origination aspects of the algorithm */

package pqacfg

type OriginatorCfg struct {
	Targets         map[TargetIdentifier]TargetCfg  `yaml:"optimization targets"`
	OriginationCfgs map[uint16][][]TargetIdentifier `yaml:"origination order"`
}

type TargetCfg struct {
	Quality    QualityIdentifier   `yaml:"quality"`
	Direction  DirectionIdentifier `yaml:"direction"`
	Uniquifier uint32              `yaml:"uniquifier"`
}
