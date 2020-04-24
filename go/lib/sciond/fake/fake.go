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
	"github.com/scionproto/scion/go/proto"
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
			path.creationTime = c.creationTime
			lifetime := time.Duration(path.JSONExpirationTimestamp) * time.Second
			path.expirationTime = path.creationTime.Add(lifetime)
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
	JSONFingerprint string   `json:"fingerprint"`
	JSONNextHop     *UDPAddr `json:"next_hop,omitempty"`
	JSONIA          addr.IA  `json:"ia"`
	// JSONExpirationTimestamp contains the point in time when the path expires, in seconds,
	// relative to the time of fake connector creation. Negative timestamps are also supported, and
	// would mean SCIOND served a path that expired in the past.
	JSONExpirationTimestamp int `json:"expiration_timestamp"`

	// creationTime contains the time when this object was constructed.
	creationTime time.Time
	// expirationTime contains the time when this path expires.
	expirationTime time.Time
}

func (p Path) Fingerprint() snet.PathFingerprint {
	return snet.PathFingerprint(p.JSONFingerprint)
}

func (p Path) UnderlayNextHop() *net.UDPAddr {
	return (*net.UDPAddr)(p.JSONNextHop)
}

func (p Path) Path() *spath.Path {
	return DummyPath()
}

// DummyPath creates a path that is reversible.
func DummyPath() *spath.Path {
	return &spath.Path{
		Raw:    make(common.RawBytes, spath.InfoFieldLength+2*spath.HopFieldLength),
		HopOff: spath.InfoFieldLength,
	}
}

func (p Path) Interfaces() []snet.PathInterface {
	return []snet.PathInterface{}
}

func (p Path) Destination() addr.IA {
	return p.JSONIA
}

func (p Path) MTU() uint16 {
	return 1472
}

func (p Path) Expiry() time.Time {
	return p.expirationTime
}

func (p Path) Copy() snet.Path {
	return &Path{
		JSONFingerprint: p.JSONFingerprint,
		JSONNextHop: &UDPAddr{
			IP:   append(p.JSONNextHop.IP[:0:0], p.JSONNextHop.IP...),
			Port: p.JSONNextHop.Port,
			Zone: p.JSONNextHop.Zone,
		},
		JSONIA:                  p.JSONIA,
		JSONExpirationTimestamp: p.JSONExpirationTimestamp,
		creationTime:            p.creationTime,
		expirationTime:          p.expirationTime,
	}
}

func (p Path) String() string {
	return fmt.Sprintf("FakePath(IA: %v, NextHop: %v, Fingerprint: %v)",
		p.JSONIA, p.JSONNextHop, p.JSONFingerprint)
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
	intMax := int(flags.PathCount)

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

	if intMax > len(entry.Paths) {
		intMax = len(entry.Paths)
	}
	return c.adapter(entry.Paths[:intMax]), nil
}

func (c connector) adapter(paths []*Path) []snet.Path {
	var snetPaths []snet.Path
	for _, path := range paths {
		snetPaths = append(snetPaths, path.Copy())
	}
	return snetPaths
}

func (c connector) LocalIA(ctx context.Context) (addr.IA, error) {
	panic("not implemented")
}

func (c connector) ASInfo(ctx context.Context, ia addr.IA) (*sciond.ASInfoReply, error) {
	panic("not implemented")
}

func (c connector) IFInfo(ctx context.Context,
	ifs []common.IFIDType) (map[common.IFIDType]*net.UDPAddr, error) {

	panic("not implemented")
}

func (c connector) SVCInfo(ctx context.Context,
	svcTypes []proto.ServiceType) (*sciond.ServiceInfoReply, error) {

	panic("not implemented")
}

func (c connector) RevNotificationFromRaw(ctx context.Context, b []byte) (*sciond.RevReply, error) {
	panic("not implemented")
}

func (c connector) RevNotification(ctx context.Context,
	sRevInfo *path_mgmt.SignedRevInfo) (*sciond.RevReply, error) {

	panic("not implemented")
}

func (c connector) Close(ctx context.Context) error {
	return nil
}
