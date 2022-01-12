package pqa_extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToFromPb(t *testing.T) {
	tests := map[string]Extension{
		"latency": {
			Uniquifier: 2,
			Direction:  Forward,
			Quality:    Latency,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			after := FromPB(test.ToPB())
			assert.Equal(t, test, *after)
		})
	}
}
