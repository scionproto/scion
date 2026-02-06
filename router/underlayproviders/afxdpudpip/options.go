package afxdpudpip

import (
	"strconv"
	"strings"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// parseOptions parses the link options string and extracts the queue ID.
// Options format: "queue=N" where N is the queue number (default 0).
// Multiple options can be separated by commas, e.g., "queue=2,other=value".
func parseOptions(options string) (queueID uint32, err error) {
	if options == "" {
		return 0, nil
	}
	for opt := range strings.SplitSeq(options, ",") {
		opt = strings.TrimSpace(opt)
		if key, value, found := strings.Cut(opt, "="); found {
			switch strings.TrimSpace(key) {
			case "queue":
				v, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
				if err != nil {
					return 0, serrors.Wrap("invalid queue option", err, "value", value)
				}
				queueID = uint32(v)
			default:
				log.Info("Ignoring unknown AF_XDP underlay option",
					"key", key, "value", value)
			}
		}
	}
	return queueID, nil
}
