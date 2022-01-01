package config

import (
	"testing"

	pqa "github.com/scionproto/scion/go/pkg/pqabeaconing"

	"github.com/stretchr/testify/assert"
)

func TestLoadingOriginatorCfgWellformed(t *testing.T) {
	tests := map[string]OriginatorCfg{
		"testcfgs/originator/config.yml": {
			OptimizationTargets: map[OptimizationTargetIdentifierCfg]OptimizationTargetCfg{
				"my_target_0": {
					Quality:    "latency",
					Direction:  "forward",
					Uniquifier: 1,
				},
				"my_target_1": {
					Quality:   "latency",
					Direction: "backward",
				},
			},
			OriginationCfgs: map[IntfId]OriginationCfg{
				"intf1": {
					{"my_target_0", "NO_TARGET"},
					{"my_target_1"},
				},
				"intf2": {
					{"NO_TARGET"},
				},
			},
		},
	}

	for test, expected := range tests {
		t.Run(test, func(t *testing.T) {
			actual := LoadOriginatorCfgYAML(test)
			assert.Equal(t, expected, *actual)
		})
	}
}

func TestGeneratingOriginator(t *testing.T) {
	cfg := LoadOriginatorCfgYAML("test/originator/config.yml")
	actual, err := cfg.Generate()

	if err != nil {
		t.Fail()
	}

	expected := pqa.OriginationSettings{
		OptimizationTargets: map[pqa.OptimizationTargetIdentifier]pqa.OptimizationTarget{
			"my_target_0": {
				Quality:    "latency",
				Direction:  "forward",
				Uniquifier: 1,
			},
			"my_target_1": {
				Quality:   "latency",
				Direction: "backward",
			},
		},
		OriginationOrder: map[pqa.Ifid][][]pqa.OptimizationTargetIdentifier{
			"intf1": {
				{
					pqa.OptimizationTargetIdentifier("my_target_0"),
					pqa.OptimizationTargetIdentifier("NO_TARGET"),
				},
				{
					pqa.OptimizationTargetIdentifier("my_target_1"),
				},
			},
			"intf2": {
				{
					pqa.OptimizationTargetIdentifier("NO_TARGET"),
				},
			},
		},
	}

	assert.Equal(t, expected, actual)
}
