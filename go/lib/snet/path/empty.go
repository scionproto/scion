package path

import (
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
)

type Empty struct{}

func (e Empty) SetPath(s *slayers.SCION) error {
	s.Path, s.PathType = empty.Path{}, empty.PathType
	return nil
}
