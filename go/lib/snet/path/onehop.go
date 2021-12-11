package path

import (
	"crypto/rand"
	"hash"
	"math/big"
	"time"

	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/util"
)

type OneHop struct {
	Info      path.InfoField
	FirstHop  path.HopField
	SecondHop path.HopField
}

func (p OneHop) SetPath(s *slayers.SCION) error {
	ohp := &onehop.Path{
		Info:      p.Info,
		FirstHop:  p.FirstHop,
		SecondHop: p.SecondHop,
	}
	s.Path, s.PathType = ohp, ohp.Type()
	return nil
}

// NewOneHop creates a onehop path that has the first hopfield initialized.
func NewOneHop(egress uint16, timestamp time.Time, expiration uint8,
	mac hash.Hash) (OneHop, error) {

	segID, err := rand.Int(rand.Reader, big.NewInt(1<<16))
	if err != nil {
		return OneHop{}, err
	}
	ohp := OneHop{
		Info: path.InfoField{
			ConsDir:   true,
			Timestamp: util.TimeToSecs(timestamp),
			SegID:     uint16(segID.Uint64()),
		},
		FirstHop: path.HopField{
			ConsEgress: egress,
			ExpTime:    expiration,
		},
	}
	ohp.FirstHop.Mac = path.MAC(mac, &ohp.Info, &ohp.FirstHop, nil)
	return ohp, nil
}
