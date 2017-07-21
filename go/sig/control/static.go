package control

import "github.com/netsec-ethz/scion/go/sig/base"

type StaticRP struct {
	SDB    *base.Topology
	File   string
	Routes map[string]string
	Device string
}

func NewStaticRP(sdb *base.Topology) *StaticRP {
	return &StaticRP{SDB: sdb}
}

func (rp *StaticRP) AddRoute(destination string, isdas string) error {
	return rp.SDB.AddRoute(destination, isdas)
}

func (rp *StaticRP) DelRoute(destination string, isdas string) error {
	return rp.SDB.DelRoute(destination, isdas)
}

func (rp *StaticRP) AddSig(isdas string, encapAddr string, encapPort string, ctrlAddr string, ctrlPort string) error {
	return rp.SDB.AddSig(isdas, encapAddr, encapPort, ctrlAddr, ctrlPort, "static")
}

func (rp *StaticRP) DelSig(isdas string, address string, port string) error {
	return rp.SDB.DelSig(isdas, address, port, "static")
}

func (rp *StaticRP) Print() string {
	return rp.SDB.Print("static")
}
