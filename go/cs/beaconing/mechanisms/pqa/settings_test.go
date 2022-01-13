package pqa

import (
	"testing"

	pqacfg "github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa/config"
	"github.com/stretchr/testify/assert"
)

func TestParseOriginatorConfig(t *testing.T) {
	conf, err := pqacfg.LoadPqaCfgFromYAML("testdata/test.yml")
	assert.NoError(t, err)

	assert.NotZero(t, conf.Origination)

	set, err := NewOriginationSettings(conf.Origination)
	assert.NoError(t, err)

	assert.NotNil(t, set.Orders)
	assert.NotZero(t, len(set.Orders))

}

func TestParsePropagatorConfig(t *testing.T) {
	scen := NewScenario(t, "testdata/topo.json")
	conf, err := pqacfg.LoadPqaCfgFromYAML("testdata/test.yml")
	assert.NoError(t, err)
	assert.NotZero(t, conf.Origination)

	set, err := NewPropagationSettings(&conf.Propagation, scen.Interfaces)
	assert.NoError(t, err)

	// Check intf groups are set
	assert.NotZero(t, set.GetInterfaceGroups(pqacfg.StringToQuality("latency"), pqacfg.StringToDirection("forward")))
	assert.NotZero(t, set.GetInterfaceGroups(pqacfg.StringToQuality("latency"), pqacfg.StringToDirection("backward")))
	assert.NotZero(t, set.GetInterfaceGroups(pqacfg.StringToQuality("throughput"), pqacfg.StringToDirection("forward")))
	assert.Zero(t, set.GetInterfaceGroups(pqacfg.StringToQuality("throughput"), pqacfg.StringToDirection("backward")))

	// Check different intf groups of same quality are merged
	assert.Len(t, set.GetInterfaceGroups(pqacfg.StringToQuality("throughput"), pqacfg.StringToDirection("forward")), 5)
	assert.Len(t, set.GetInterfaceGroups(pqacfg.StringToQuality("latency"), pqacfg.StringToDirection("forward")), 3)
}

func TestGenerateSettings(t *testing.T) {
	scen := NewScenario(t, "testdata/topo.json")

	set, err := GenerateSettingsForInterfaces(scen.Interfaces)
	assert.NoError(t, err)

	assert.NotNil(t, set)

}
