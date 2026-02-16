package afxdpudpip

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/underlay/afxdp"
)

// Options represents the parsed JSON configuration for an AF_XDP underlay link.
type Options struct {
	Queue           []uint32 `json:"queue,omitempty"`
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
	if opts.Queue != nil && len(opts.Queue) == 0 {
		return Options{}, serrors.New("empty queue list")
	}
	// Deduplicate queue IDs while preserving order.
	if len(opts.Queue) > 1 {
		seen := make(map[uint32]struct{}, len(opts.Queue))
		deduped := make([]uint32, 0, len(opts.Queue))
		for _, q := range opts.Queue {
			if _, ok := seen[q]; !ok {
				seen[q] = struct{}{}
				deduped = append(deduped, q)
			}
		}
		opts.Queue = deduped
	}

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
	return opts, nil
}
