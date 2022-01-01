package config

import (
	"testing"

	pqa "github.com/scionproto/scion/go/pkg/pqabeaconing"
	"github.com/stretchr/testify/assert"
)

func TestLoadPropagatorCfgWellFormed(t *testing.T) {
	tests := map[string]PropagatorCfg{
		"testcfgs/propagator/config.yml": {
			"interface_group_foo": {
				Interfaces: []IntfId{
					"intf1",
					"intf2",
					"intf3",
				},
				OptimizationTargetFilters: []OptimizationTargetFilter{
					{
						Quality: "latency",
					},
					{
						Quality:   "throughput",
						Direction: "forward",
					},
				},
			},
		},
	}

	for file, expected := range tests {
		t.Run(file, func(t *testing.T) {
			actual := LoadPropagatorCfgYAML(file)
			assert.Equal(t, expected, *actual)
		})
	}

}

func TestGeneratingPropagator(t *testing.T) {
	tests := map[string]pqa.PropagationSettings{
		"testcfgs/propagator/config.yml": {
			IdentifierToInterfaceGroup: map[pqa.InterfaceGroupIdentifier]pqa.InterfaceGroup{
				"interface_group_foo": {
					"intf1",
					"intf2",
					"intf3",
				},
			},
			QualityToDirectionToInterfaceGroups: map[pqa.PathQualityIdentifier]map[pqa.OptimizationDirection][]pqa.InterfaceGroupIdentifier{
				"latency": {
					"forward": {
						"interface_group_foo",
					},
					"backward": {
						"interface_group_foo",
					},
				},
				"throughput": {
					"forward": {
						"interface_group_foo",
					},
				},
			},
		},
	}

	for file, expected := range tests {
		t.Run(file, func(t *testing.T) {
			cfg := LoadPropagatorCfgYAML(file)
			actual, err := cfg.Generate()

			if err != nil {
				t.Fail()
			}

			assert.Equal(t, expected, actual)
		})
	}
}
