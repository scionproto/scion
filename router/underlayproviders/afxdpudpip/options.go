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

//go:build linux && (amd64 || arm64)

package afxdpudpip

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/underlay/afxdp"
)

// Options represents the parsed JSON configuration for an AF_XDP underlay link.
type Options struct {
	RxQueues        []uint32 `json:"rx_queues,omitempty"`
	TxQueues        []uint32 `json:"tx_queues,omitempty"`
	PreferZerocopy  *bool    `json:"prefer_zerocopy,omitempty"`
	PreferHugepages *bool    `json:"prefer_hugepages,omitempty"`
	NumFrames       *uint32  `json:"num_frames,omitempty"`
	FrameSize       *uint32  `json:"frame_size,omitempty"`
	RxSize          *uint32  `json:"rx_size,omitempty"`
	TxSize          *uint32  `json:"tx_size,omitempty"`
	CqSize          *uint32  `json:"cq_size,omitempty"`
	BatchSize       *uint32  `json:"batch_size,omitempty"`
}

func isPowerOfTwo(v uint32) bool {
	return v > 0 && v&(v-1) == 0
}

func validatePowerOfTwo(name string, v *uint32) error {
	if v != nil && !isPowerOfTwo(*v) {
		return serrors.New(fmt.Sprintf("%s must be a power of two, got %d", name, *v))
	}
	return nil
}

func validateNonZero(name string, v *uint32) error {
	if v != nil && *v == 0 {
		return serrors.New(fmt.Sprintf("%s must not be zero", name))
	}
	return nil
}

// deduplicateQueues removes duplicate queue IDs while preserving order.
// Returns nil if the input is nil.
func deduplicateQueues(queues []uint32) []uint32 {
	if len(queues) <= 1 {
		return queues
	}
	seen := make(map[uint32]struct{}, len(queues))
	deduped := make([]uint32, 0, len(queues))
	for _, q := range queues {
		if _, ok := seen[q]; !ok {
			seen[q] = struct{}{}
			deduped = append(deduped, q)
		}
	}
	return deduped
}

// parseOptions parses the JSON options string.
// Returns zero-value Options if the string is empty.
func parseOptions(options string) (Options, error) {
	if options == "" {
		return Options{}, nil
	}
	dec := json.NewDecoder(strings.NewReader(options))
	dec.DisallowUnknownFields()
	var opts Options
	if err := dec.Decode(&opts); err != nil {
		return Options{}, serrors.Wrap("invalid options JSON", err)
	}
	if opts.RxQueues != nil && len(opts.RxQueues) == 0 {
		return Options{}, serrors.New("empty rx_queues list")
	}
	if opts.TxQueues != nil && len(opts.TxQueues) == 0 {
		return Options{}, serrors.New("empty tx_queues list")
	}
	// Deduplicate queue IDs while preserving order.
	opts.RxQueues = deduplicateQueues(opts.RxQueues)
	opts.TxQueues = deduplicateQueues(opts.TxQueues)

	// Validate ring/frame sizes: must be non-zero and power of two.
	for _, check := range []struct {
		name string
		val  *uint32
	}{
		{"num_frames", opts.NumFrames},
		{"frame_size", opts.FrameSize},
		{"rx_size", opts.RxSize},
		{"tx_size", opts.TxSize},
		{"cq_size", opts.CqSize},
	} {
		if err := validatePowerOfTwo(check.name, check.val); err != nil {
			return Options{}, err
		}
	}
	// batch_size must be non-zero but need not be a power of two.
	if err := validateNonZero("batch_size", opts.BatchSize); err != nil {
		return Options{}, err
	}
	if opts.FrameSize != nil && *opts.FrameSize < afxdp.DefaultFrameSize {
		return Options{}, serrors.New(
			fmt.Sprintf("frame_size must be >= %d (default), got %d",
				afxdp.DefaultFrameSize, *opts.FrameSize),
		)
	}
	if opts.FrameSize != nil && *opts.FrameSize > uint32(os.Getpagesize()) {
		return Options{}, serrors.New(
			fmt.Sprintf("frame_size must be <= system page size (%d), got %d",
				os.Getpagesize(), *opts.FrameSize),
		)
	}
	return opts, nil
}
