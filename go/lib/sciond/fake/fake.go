// Copyright 2019 Anapaya Systems

package fake

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

// New creates a new fake SCIOND implementation using the data in the script.
//
// New also initializes path expiry times according to the expiry seconds in the script.
func New(script *Script) sciond.Connector {
	c := &connector{
		script:       script,
		creationTime: time.Now(),
	}
	for _, entry := range script.Entries {
		for _, path := range entry.Paths {
			creationTime := c.creationTime
			lifetime := time.Duration(path.JSONExpirationTimestamp) * time.Second
			path.metadata = pathMetadata{
				creationTime:   creationTime,
				expirationTime: creationTime.Add(lifetime),
			}
		}
	}
	return c
}

// NewFromFile creates a new fake SCIOND implementation using the JSON representation in the file.
func NewFromFile(file string) (sciond.Connector, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, serrors.WrapStr("unable to read script from file", err)
	}
	var script Script
	if err := json.Unmarshal(b, &script); err != nil {
		return nil, serrors.WrapStr("unable to unmarshal script from JSON", err)
	}
	return New(&script), nil
}

// Script describes the path entries a fake SCIOND should respond with.
type Script struct {
	IA      addr.IA  `json:"ia"`
	Entries []*Entry `json:"entries"`
}

// Entry describes a path reply.
type Entry struct {
	// ReplyStartTimestamp describes the number of seconds that should pass after a fake SCIOND has
	// been created before serving paths from the entry. The last entry whose timestamp has passed
	// is selected. (so, if the seconds timestamps are 0, 4, 6, the paths selected at 5 seconds from
	// creation would be the ones associated with timestamp 4)
	ReplyStartTimestamp int `json:"reply_start_timestamp"`
	// Paths contains the paths for a fake SCIOND reply.
	Paths []*Path `json:"paths"`
}

type Path struct {
	// JSONInterfaces encodes a list of interfaces
	JSONInterfaces []PathInterface `json:"interfaces,omitempty"`
	JSONNextHop    *UDPAddr        `json:"next_hop,omitempty"`
	// JSONExpirationTimestamp contains the point in time when the path expires, in seconds,
	// relative to the time of fake connector creation. Negative timestamps are also supported, and
	// would mean SCIOND served a path that expired in the past.
	JSONExpirationTimestamp int `json:"expiration_timestamp"`

	metadata pathMetadata
}

func (p Path) UnderlayNextHop() *net.UDPAddr {
	return (*net.UDPAddr)(p.JSONNextHop)
}

func (p Path) Path() spath.Path {
	return DummyPath()
}

// DummyPath creates a path that is reversible.
func DummyPath() spath.Path {
	return spath.Path{}
}

func (p Path) Interfaces() []snet.PathInterface {
	ifaces := make([]snet.PathInterface, len(p.JSONInterfaces))
	for i, jsonIface := range p.JSONInterfaces {
		ifaces[i] = snet.PathInterface{IA: jsonIface.IA, ID: jsonIface.ID}
	}
	return ifaces
}

func (p Path) Destination() addr.IA {
	return p.JSONInterfaces[len(p.JSONInterfaces)-1].IA
}

func (p Path) Metadata() snet.PathMetadata {
	return p.metadata
}

func (p Path) Copy() snet.Path {
	return &Path{
		JSONInterfaces: p.JSONInterfaces,
		JSONNextHop: &UDPAddr{
			IP:   append(p.JSONNextHop.IP[:0:0], p.JSONNextHop.IP...),
			Port: p.JSONNextHop.Port,
			Zone: p.JSONNextHop.Zone,
		},
		JSONExpirationTimestamp: p.JSONExpirationTimestamp,
		metadata:                p.metadata,
	}
}

func (p Path) String() string {
	return fmt.Sprintf("FakePath(Dest: %v, NextHop: %v, Fingerprint: %v)",
		p.Destination(), p.JSONNextHop, snet.Fingerprint(p))
}

type PathInterface struct {
	IA addr.IA         `json:"ia"`
	ID common.IFIDType `json:"id"`
}

type pathMetadata struct {
	// creationTime contains the time when this object was constructed.
	creationTime time.Time
	// expirationTime contains the time when this path expires.
	expirationTime time.Time
}

func (m pathMetadata) MTU() uint16 {
	return 1472
}

func (m pathMetadata) Expiry() time.Time {
	return m.expirationTime
}

// UDPAddr decorates net.UDPAddr with custom JSON marshaling logic.
type UDPAddr net.UDPAddr

func (u *UDPAddr) MarshalText() ([]byte, error) {
	s := (*net.UDPAddr)(u).String()
	return []byte(s), nil
}

func (u *UDPAddr) UnmarshalText(text []byte) error {
	address, err := net.ResolveUDPAddr("udp", string(text))
	if err != nil {
		return err
	}
	*u = UDPAddr(*address)
	if u.IP.To4() != nil {
		u.IP = u.IP.To4()
	}
	return nil
}

type connector struct {
	creationTime time.Time

	script *Script
}

func (c connector) Paths(_ context.Context, _, _ addr.IA,
	flags sciond.PathReqFlags) ([]snet.Path, error) {

	secondsElapsed := int(time.Since(c.creationTime).Seconds())

	var entry *Entry
	for i := 0; i < len(c.script.Entries); i++ {
		entry = c.script.Entries[i]
		if secondsElapsed <= entry.ReplyStartTimestamp {
			break
		}
	}
	if entry == nil {
		return nil, serrors.New("path not found")
	}
	return c.adapter(entry.Paths), nil
}

func (c connector) adapter(paths []*Path) []snet.Path {
	var snetPaths []snet.Path
	for _, path := range paths {
		snetPaths = append(snetPaths, path.Copy())
	}
	return snetPaths
}

func (c connector) LocalIA(ctx context.Context) (addr.IA, error) {
	return c.script.IA, nil
}

func (c connector) ASInfo(ctx context.Context, ia addr.IA) (sciond.ASInfo, error) {
	panic("not implemented")
}

func (c connector) IFInfo(ctx context.Context,
	ifs []common.IFIDType) (map[common.IFIDType]*net.UDPAddr, error) {

	panic("not implemented")
}

func (c connector) SVCInfo(ctx context.Context,
	svcTypes []addr.HostSVC) (map[addr.HostSVC]string, error) {

	panic("not implemented")
}

func (c connector) RevNotificationFromRaw(ctx context.Context, b []byte) error {
	panic("not implemented")
}

func (c connector) RevNotification(ctx context.Context,
	sRevInfo *path_mgmt.SignedRevInfo) error {

	panic("not implemented")
}

func (c connector) Close(ctx context.Context) error {
	return nil
}
