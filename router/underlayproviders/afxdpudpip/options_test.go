// Copyright 2026 SCION Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package afxdpudpip

import (
	"testing"

	"github.com/scionproto/scion/pkg/private/ptr"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOptions(t *testing.T) {
	tests := map[string]struct {
		options       string
		wantQueue     []uint32
		wantZerocopy  *bool
		wantHugepages *bool
		wantNumFrames *uint32
		wantFrameSize *uint32
		wantRxSize    *uint32
		wantTxSize    *uint32
		wantCqSize    *uint32
		wantBatchSize *uint32
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
		"prefer_zerocopy true": {
			options:      `{"prefer_zerocopy": true}`,
			wantZerocopy: ptr.To(true),
		},
		"prefer_zerocopy false": {
			options:      `{"prefer_zerocopy": false}`,
			wantZerocopy: ptr.To(false),
		},
		"prefer_hugepages true": {
			options:       `{"prefer_hugepages": true}`,
			wantHugepages: ptr.To(true),
		},
		"prefer_hugepages false": {
			options:       `{"prefer_hugepages": false}`,
			wantHugepages: ptr.To(false),
		},
		"num_frames": {
			options:       `{"num_frames": 8192}`,
			wantNumFrames: ptr.To(uint32(8192)),
		},
		"frame_size": {
			options:       `{"frame_size": 4096}`,
			wantFrameSize: ptr.To(uint32(4096)),
		},
		"rx_size": {
			options:    `{"rx_size": 1024}`,
			wantRxSize: ptr.To(uint32(1024)),
		},
		"tx_size": {
			options:    `{"tx_size": 1024}`,
			wantTxSize: ptr.To(uint32(1024)),
		},
		"cq_size": {
			options:    `{"cq_size": 4096}`,
			wantCqSize: ptr.To(uint32(4096)),
		},
		"batch_size": {
			options:       `{"batch_size": 128}`,
			wantBatchSize: ptr.To(uint32(128)),
		},
		"all options": {
			options: `{
				"queue": [0, 1],
				"prefer_zerocopy": false,
				"prefer_hugepages": true,
				"num_frames": 8192,
				"frame_size": 4096,
				"rx_size": 1024,
				"tx_size": 1024,
				"cq_size": 4096,
				"batch_size": 128
			}`,
			wantQueue:     []uint32{0, 1},
			wantZerocopy:  ptr.To(false),
			wantHugepages: ptr.To(true),
			wantNumFrames: ptr.To(uint32(8192)),
			wantFrameSize: ptr.To(uint32(4096)),
			wantRxSize:    ptr.To(uint32(1024)),
			wantTxSize:    ptr.To(uint32(1024)),
			wantCqSize:    ptr.To(uint32(4096)),
			wantBatchSize: ptr.To(uint32(128)),
		},
		"err exceeds uint32 range": {
			options: `{"queue": [4294967296]}`,
			wantErr: true,
		},
		"err negative queue value": {
			options: `{"queue": [-1]}`,
			wantErr: true,
		},
		"err empty queue list": {
			options: `{"queue": []}`,
			wantErr: true,
		},
		"err num_frames zero": {
			options: `{"num_frames": 0}`,
			wantErr: true,
		},
		"err num_frames not power of two": {
			options: `{"num_frames": 3000}`,
			wantErr: true,
		},
		"err frame_size zero": {
			options: `{"frame_size": 0}`,
			wantErr: true,
		},
		"err frame_size not power of two": {
			options: `{"frame_size": 3000}`,
			wantErr: true,
		},
		"err frame_size too small": {
			options: `{"frame_size": 1024}`,
			wantErr: true,
		},
		"err rx_size zero": {
			options: `{"rx_size": 0}`,
			wantErr: true,
		},
		"err rx_size not power of two": {
			options: `{"rx_size": 100}`,
			wantErr: true,
		},
		"err tx_size zero": {
			options: `{"tx_size": 0}`,
			wantErr: true,
		},
		"err tx_size not power of two": {
			options: `{"tx_size": 100}`,
			wantErr: true,
		},
		"err cq_size zero": {
			options: `{"cq_size": 0}`,
			wantErr: true,
		},
		"err cq_size not power of two": {
			options: `{"cq_size": 100}`,
			wantErr: true,
		},
		"err batch_size zero": {
			options: `{"batch_size": 0}`,
			wantErr: true,
		},
		"err unknown field rejected": {
			options: `{"unknown": "value"}`,
			wantErr: true,
		},
		"err invalid JSON": {
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
			assert.Equal(t, tt.wantNumFrames, opts.NumFrames)
			assert.Equal(t, tt.wantFrameSize, opts.FrameSize)
			assert.Equal(t, tt.wantRxSize, opts.RxSize)
			assert.Equal(t, tt.wantTxSize, opts.TxSize)
			assert.Equal(t, tt.wantCqSize, opts.CqSize)
			assert.Equal(t, tt.wantBatchSize, opts.BatchSize)
		})
	}
}
