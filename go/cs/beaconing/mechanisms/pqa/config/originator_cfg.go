/* This file contains types and functions related to the origination aspects of the algorithm */

package pqacfg

import (
	"errors"
	"strconv"

	"github.com/scionproto/scion/go/lib/serrors"
)

type OriginatorCfg struct {
	OptimizationTargets map[OptimizationTargetIdentifierCfg]OptimizationTargetCfg `yaml:"optimization targets"`
	OriginationCfgs     map[IntfId]OriginationCfg                                 `yaml:"origination order"`
}

type OptimizationTargetCfg struct {
	Quality    PathQualityIdentifierCfg `yaml:"quality"`
	Direction  OptimizationDirectionCfg `yaml:"direction"`
	Uniquifier uint8                    `yaml:"uniquifier"`
}

type OriginationCfg [][]OptimizationTargetIdentifierCfg

type OptimizationTargetIdentifierCfg string

type OptimizationDirectionCfg string

func (id IntfId) Uint16() (uint16, error) {
	if intfId_i, err := strconv.ParseInt(string(id), 10, 16); err != nil {
		return 0, serrors.WrapStr("error parsing Interface id", err, "ifid", id)
	} else {
		return uint16(intfId_i), nil
	}
}

func (cfg *OriginatorCfg) Validate() error {
	for _, targetCfg := range cfg.OptimizationTargets {
		if err := targetCfg.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (cfg *OptimizationTargetCfg) Validate() error {
	if cfg.Quality == "" {
		return errors.New("missing quality")
	}

	if cfg.Direction == "" {
		return errors.New("missing direction")
	}

	return nil

}
