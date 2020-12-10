package epic

import (
	"encoding/binary"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
)

const PathType path.Type = 3

func RegisterPath() {
	path.RegisterPath(path.Metadata{
		Type: PathType,
		Desc: "Epic",
		New: func() path.Path {
			return &EpicPath{ScionRaw: &scion.Raw{}}
		},
	})
}

type EpicPath struct {
	PacketTimestamp uint64
	PHVF            []byte
	LHVF            []byte
	ScionRaw        *scion.Raw
}

func (p *EpicPath) SerializeTo(b []byte) error {
	if p == nil {
		return serrors.New("epic path must not be nil")
	}
	if len(b) < 16 {
		return serrors.New("buffer for EpicPath too short (< 16 bytes)")
	}
	if len(p.PHVF) != 4 || len(p.LHVF) != 4 {
		return serrors.New("PHVF and LHVF must have 4 bytes",
			"PHVF", len(p.PHVF), "LHVF", len(p.LHVF))
	}
	if p.ScionRaw == nil {
		return serrors.New("scion subheader must exist")
	}
	binary.BigEndian.PutUint64(b[:8], p.PacketTimestamp)
	copy(b[8:12], p.PHVF)
	copy(b[12:16], p.LHVF)
	return p.ScionRaw.SerializeTo(b[16:])
}

func (p *EpicPath) DecodeFromBytes(b []byte) error {
	if p == nil {
		return serrors.New("epic path must not be nil")
	}
	if len(b) < 16 {
		return serrors.New("EpicPath bytes too short (< 16 bytes)")
	}
	p.PacketTimestamp = binary.BigEndian.Uint64(b[:8])
	p.PHVF = make([]byte, 4)
	p.LHVF = make([]byte, 4)
	copy(p.PHVF, b[8:12])
	copy(p.LHVF, b[12:16])
	p.ScionRaw = &scion.Raw{}
	return p.ScionRaw.DecodeFromBytes(b[16:])
}

func (p *EpicPath) Reverse() (path.Path, error) {
	if p == nil {
		return nil, serrors.New("epic path must not be nil")
	}
	if p.ScionRaw == nil {
		return nil, serrors.New("scion subpath must not be nil")
	}
	revScion, err := p.ScionRaw.Reverse()
	if err != nil {
		return nil, err
	}
	scionRaw, ok := revScion.(*scion.Raw)
	if !ok {
		return nil, err
	}
	p.ScionRaw = scionRaw
	return p, nil
}

func (p *EpicPath) Len() int {
	if p == nil {
		return 0
	}
	if p.ScionRaw == nil {
		return 16
	}
	return 16 + p.ScionRaw.Len()
}

func (p *EpicPath) Type() path.Type {
	return PathType
}
