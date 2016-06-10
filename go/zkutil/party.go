package zkutil

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/samuel/go-zookeeper/zk"
)

type Party struct {
	c    *zk.Conn
	ISD  int
	AS   int
	path string
	name string
}

func NewParty(c *zk.Conn, isd, as int, name string) *Party {
	return &Party{c, isd, as, fmt.Sprintf(isdAsPath(isd, as)), name}
}

func (p *Party) Join() error {
	if err := EnsurePath(p.c, p.path); err != nil {
		return err
	}
	acl := zk.WorldACL(zk.PermAll)
	path, err := p.c.CreateProtectedEphemeralSequential(
		fmt.Sprintf("%s/%s", p.path, p.name), []byte(p.name), acl)
	if err != nil {
		return err
	}
	glog.Infof("(party) Joined: %v", path)
	return nil
}
