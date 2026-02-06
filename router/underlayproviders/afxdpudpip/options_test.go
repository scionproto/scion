package afxdpudpip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOptions(t *testing.T) {
	tests := map[string]struct {
		options     string
		wantQueueID uint32
		wantErr     bool
	}{
		"empty string": {
			options: "",
		},
		"queue option": {
			options:     "queue=5",
			wantQueueID: 5,
		},
		"queue option with spaces": {
			options:     " queue = 3 ",
			wantQueueID: 3,
		},
		"queue zero": {
			options: "queue=0",
		},
		"multiple options with queue": {
			options:     "other=value,queue=7,another=123",
			wantQueueID: 7,
		},
		"unknown option ignored": {
			options: "unknown=value",
		},
		"max uint32 queue value": {
			options:     "queue=4294967295",
			wantQueueID: 4294967295,
		},
		"exceeds uint32 range": {
			options: "queue=4294967296",
			wantErr: true,
		},
		"invalid queue value": {
			options: "queue=notanumber",
			wantErr: true,
		},
		"negative queue value": {
			options: "queue=-1",
			wantErr: true,
		},
		"queue value too large": {
			options: "queue=4294967296",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			queueID, err := parseOptions(tt.options)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantQueueID, queueID)
		})
	}
}
