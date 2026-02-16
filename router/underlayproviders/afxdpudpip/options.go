package afxdpudpip

import (
	"encoding/json"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// Options represents the parsed JSON configuration for an AF_XDP underlay link.
type Options struct {
	Queue           []uint32 `json:"queue,omitempty"`
	PreferZerocopy  *bool    `json:"prefer_zerocopy,omitempty"`
	PreferHugepages *bool    `json:"prefer_hugepages,omitempty"`
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
		seen := make(map[uint32]bool, len(opts.Queue))
		deduped := opts.Queue[:0]
		for _, q := range opts.Queue {
			if !seen[q] {
				seen[q] = true
				deduped = append(deduped, q)
			}
		}
		opts.Queue = deduped
	}
	return opts, nil
}
