package pqa

import (
	"fmt"
	"testing"

	pqacfg "github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa/config"
	"github.com/stretchr/testify/assert"
)

func TestPathQualityComparison(t *testing.T) {
	type PathQualityComparisonTest struct {
		PathQuality PathQuality
		Left        float64
		Right       float64
		Expected    bool
	}

	tests := []PathQualityComparisonTest{
		{PathQuality{optimalityType: Max}, 1.0, 2.0, false},
		{PathQuality{optimalityType: Max}, 2.0, 1.0, true},
		{PathQuality{optimalityType: Min}, 1.0, 2.0, true},
		{PathQuality{optimalityType: Min}, 2.0, 1.0, false},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			actual := test.PathQuality.Compare(test.Left, test.Right)
			assert.Equal(t, test.Expected, actual)
		})
	}
}

func TestParseOriginatorConfig(t *testing.T) {
	conf, err := pqacfg.LoadPqaCfgFromYAML("testdata/test_orig.yml")
	assert.NoError(t, err)

	assert.NotZero(t, conf.Origination)

	set, err := NewOriginationSettings(conf.Origination, *NewGlobalParams())
	assert.NoError(t, err)

	assert.NotNil(t, set.Orders)
	assert.NotZero(t, len(set.Orders))

}
