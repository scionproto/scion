package config

import (
	"testing"

	pqa "github.com/scionproto/scion/go/pkg/pqabeaconing"

	"github.com/stretchr/testify/assert"
)

func TestLoadingStaticCfgWellformed(t *testing.T) {

	tests := map[string]StaticCfg{
		"testcfgs/static/config.yml": {
			BeaconsPerOPtimizationQuality: 10,
			PathQualities: map[PathQualityIdentifierCfg]PathQualityCfg{
				"latency": {
					Combination:       "additive",
					Optimality:        "min",
					SymmetryTolerance: 0.1,
				},
				"throughput": {
					Combination:       "min",
					Optimality:        "max",
					SymmetryTolerance: 0.2,
				},
			},
		},
	}

	for test, expected := range tests {
		t.Run(test, func(t *testing.T) {
			actual := LoadStaticCfgYAML(test)
			assert.Equal(t, expected, *actual)
		})
	}
}

func TestGeneratingStatic(t *testing.T) {
	tests := map[string]pqa.StaticSettings{
		"test/static/config.yml": {
			PathQualities: map[pqa.PathQualityIdentifier]pqa.PathQuality{
				"latency": {
					CombinationType:   pqa.CombinationTypeAdditive,
					OptimalityType:    pqa.OptimalityTypeMin,
					SymmetryTolerance: 0.1,
				},
				"throughput": {
					CombinationType:   pqa.CombinationTypeMin,
					OptimalityType:    pqa.OptimalityTypeMax,
					SymmetryTolerance: 0.2,
				},
			},
		},
	}

	for test, expected := range tests {
		t.Run(test, func(t *testing.T) {
			actual, err := LoadStaticCfgYAML(test).Generate()
			assert.NoError(t, err)
			assert.Equal(t, expected, actual)
		})
	}
}
