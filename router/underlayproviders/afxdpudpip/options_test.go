package afxdpudpip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func boolPtr(b bool) *bool { return &b }

func TestParseOptions(t *testing.T) {
	tests := map[string]struct {
		options       string
		wantQueue     []uint32
		wantZerocopy  *bool
		wantHugepages *bool
		wantErr       bool
	}{
		"empty string": {
			options: "",
		},
		"empty object": {
			options: `{}`,
		},
		"single queue": {
			options:   `{"queue": [5]}`,
			wantQueue: []uint32{5},
		},
		"multiple queues": {
			options:   `{"queue": [0, 1, 2, 3]}`,
			wantQueue: []uint32{0, 1, 2, 3},
		},
		"duplicate queues deduplicated": {
			options:   `{"queue": [1, 2, 1, 3, 2]}`,
			wantQueue: []uint32{1, 2, 3},
		},
		"max uint32 queue value": {
			options:   `{"queue": [4294967295]}`,
			wantQueue: []uint32{4294967295},
		},
		"exceeds uint32 range": {
			options: `{"queue": [4294967296]}`,
			wantErr: true,
		},
		"negative queue value": {
			options: `{"queue": [-1]}`,
			wantErr: true,
		},
		"empty queue list": {
			options: `{"queue": []}`,
			wantErr: true,
		},
		"prefer_zerocopy true": {
			options:      `{"prefer_zerocopy": true}`,
			wantZerocopy: boolPtr(true),
		},
		"prefer_zerocopy false": {
			options:      `{"prefer_zerocopy": false}`,
			wantZerocopy: boolPtr(false),
		},
		"prefer_hugepages true": {
			options:       `{"prefer_hugepages": true}`,
			wantHugepages: boolPtr(true),
		},
		"prefer_hugepages false": {
			options:       `{"prefer_hugepages": false}`,
			wantHugepages: boolPtr(false),
		},
		"all options": {
			options: `{
				"queue": [0, 1],
				"prefer_zerocopy": false,
				"prefer_hugepages": true
			}`,
			wantQueue:     []uint32{0, 1},
			wantZerocopy:  boolPtr(false),
			wantHugepages: boolPtr(true),
		},
		"unknown field rejected": {
			options: `{"unknown": "value"}`,
			wantErr: true,
		},
		"invalid JSON": {
			options: `not json`,
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts, err := parseOptions(tt.options)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantQueue, opts.Queue)
			assert.Equal(t, tt.wantZerocopy, opts.PreferZerocopy)
			assert.Equal(t, tt.wantHugepages, opts.PreferHugepages)
		})
	}
}
