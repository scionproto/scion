package control

import (
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/sig/base"
)

type StaticRP struct {
	SDB    *base.SDB
	File   string
	Routes map[string]string
	Device string
}

func Static(sdb *base.SDB) *StaticRP {
	return &StaticRP{SDB: sdb}
}

func (rp *StaticRP) AddRoute(destination string, isdas string) error {
	return rp.SDB.AddRoute(destination, isdas)
}

func (rp *StaticRP) DelRoute(destination string, isdas string) {
	log.Warn("Not implemented")
}

func (rp *StaticRP) AddSig(isdas string, encapAddr string, encapPort string, ctrlAddr string, ctrlPort string) {
	err := rp.SDB.AddSig(isdas, encapAddr, encapPort, ctrlAddr, ctrlPort, "static")
	if err != nil {
		log.Warn("Unable to add SIG", "err", err)
	}
}

func (rp *StaticRP) DelSig(isdas string, address string, port string) {
	err := rp.SDB.DelSig(isdas, address, port, "static")
	if err != nil {
		log.Warn("Unable to delete SIG", "err", err)
	}
}

func (rp *StaticRP) Print() string {
	return rp.SDB.Print("static")
}
