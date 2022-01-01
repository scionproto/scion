package pqa

import (
	"fmt"
	"testing"

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
		{PathQuality{OptimalityType: OptimalityTypeMax}, 1.0, 2.0, false},
		{PathQuality{OptimalityType: OptimalityTypeMax}, 2.0, 1.0, true},
		{PathQuality{OptimalityType: OptimalityTypeMin}, 1.0, 2.0, true},
		{PathQuality{OptimalityType: OptimalityTypeMin}, 2.0, 1.0, false},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			actual := test.PathQuality.Compare(test.Left, test.Right)
			assert.Equal(t, test.Expected, actual)
		})
	}
}
