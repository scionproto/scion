package renewal

import (
	"time"

	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
)

var FixedTime, _ = time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")

func NewSignedRequestFixedTime(s, r, c keyconf.Key, crt *cert.AS) ([]byte, error) {
	return newSignedRequest(s, r, c, crt, FixedTime)
}
