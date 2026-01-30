package afxdpudpip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOptions(t *testing.T) {
	tests := []struct {
		name        string
		options     string
		wantQueueID uint32
		wantErr     bool
	}{
		{
			name:        "empty string",
			options:     "",
			wantQueueID: 0,
		},
		{
			name:        "queue option",
			options:     "queue=5",
			wantQueueID: 5,
		},
		{
			name:        "queue option with spaces",
			options:     " queue = 3 ",
			wantQueueID: 3,
		},
		{
			name:        "queue zero",
			options:     "queue=0",
			wantQueueID: 0,
		},
		{
			name:        "multiple options with queue",
			options:     "other=value,queue=7,another=123",
			wantQueueID: 7,
		},
		{
			name:        "unknown option ignored",
			options:     "unknown=value",
			wantQueueID: 0,
		},
		{
			name:        "max uint32 queue value",
			options:     "queue=4294967295",
			wantQueueID: 4294967295,
		},
		{
			name:        "exceeds uint32 range",
			options:     "queue=4294967296",
			wantQueueID: 0,
			wantErr:     true,
		},
		{
			name:        "invalid queue value",
			options:     "queue=notanumber",
			wantQueueID: 0,
			wantErr:     true,
		},
		{
			name:        "negative queue value",
			options:     "queue=-1",
			wantQueueID: 0,
			wantErr:     true,
		},
		{
			name:        "queue value too large",
			options:     "queue=4294967296",
			wantQueueID: 0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
