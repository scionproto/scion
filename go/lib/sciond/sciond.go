// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sciond queries local SCIOND servers for information.
//
// To query SCIOND, initialize a Service object by passing in the path to the
// UNIX socket. It is then possible to establish connections to SCIOND by
// calling Connect or ConnectTimeout on the service. The connections implement
// interface Connector, whose methods can be used to talk to SCIOND.
//
// Connector method calls return the entire answer of SCIOND.
//
// Fields prefixed with Raw (e.g., RawErrorCode) contain data in the format
// received from SCIOND.  These are used internally, and the accessors without
// the prefix (e.g., ErrorCode()) should be used instead.
package sciond

import (
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/proto"
)

// Time to live for cache entries
const (
	ASInfoTTL  = time.Hour
	IFInfoTTL  = time.Hour
	SVCInfoTTL = 10 * time.Second
)

// Service describes a SCIOND endpoint. New connections to SCIOND can be
// initialized via Connect and ConnectTimeout.
type Service interface {
	// Connect connects to the SCIOND server described by Service. Future
	// method calls on the returned Connector request information from SCIOND.
	// The information is not guaranteed to be fresh, as the returned connector
	// caches ASInfo replies for ASInfoTTL time, IFInfo replies for IFInfoTTL
	// time and SVCInfo for SVCInfoTTL time.
	Connect() (Connector, error)
	// ConnectTimeout acts like Connect but takes a timeout.
	//
	// A negative timeout means infinite timeout.
	//
	// To check for timeout errors, type assert the returned error to
	// *net.OpError and call method Timeout().
	ConnectTimeout(timeout time.Duration) (Connector, error)
}

type service struct {
	path string
}

func NewService(name string) Service {
	return &service{
		path: name,
	}
}

func (s *service) Connect() (Connector, error) {
	return connect(s.path)
}

func (s *service) ConnectTimeout(timeout time.Duration) (Connector, error) {
	return connectTimeout(s.path, timeout)
}

// A Connector is used to query SCIOND. The connector maintains an internal
// cache for interface, service and AS information. All connector methods block until either
// an error occurs, or the method successfully returns.
type Connector interface {
	// Paths requests from SCIOND a set of end to end paths between src and
	// dst. max specifices the maximum number of paths returned.
	Paths(dst, src addr.IA, max uint16, f PathReqFlags) (*PathReply, error)
	// ASInfo requests from SCIOND information about AS ia.
	ASInfo(ia addr.IA) (*ASInfoReply, error)
	// IFInfo requests from SCIOND addresses and ports of interfaces.  Slice
	// ifs contains interface IDs of BRs. If empty, a fresh (i.e., uncached)
	// answer containing all interfaces is returned.
	IFInfo(ifs []uint64) (*IFInfoReply, error)
	// SVCInfo requests from SCIOND information about addresses and ports of
	// infrastructure services.  Slice svcTypes contains a list of desired
	// service types. If unset, a fresh (i.e., uncached) answer containing all
	// service types is returned.
	SVCInfo(svcTypes []ServiceType) (*ServiceInfoReply, error)
	// RevNotification sends a raw revocation to SCIOND, as contained in an
	// SCMP message.
	RevNotificationFromRaw(revInfo []byte) (*RevReply, error)
	// RevNotification sends a RevocationInfo message to SCIOND.
	RevNotification(revInfo *path_mgmt.RevInfo) (*RevReply, error)
	// Close shuts down the connection to a SCIOND server.
	Close() error
	// SetDeadline sets a deadline associated with any SCIOND query. If
	// underlying protocol operations exceed the deadline, the queries return
	// immediately with an error.
	//
	// A zero value for t means queries will not time out.
	//
	// To check for exceeded deadlines, type assert the returned error to
	// *net.OpError and call method Timeout().
	//
	// Following a timeout error the underlying protocol to SCIOND is probably
	// desynchronized. Establishing a fresh connection to SCIOND is
	// recommended.
	SetDeadline(t time.Time) error
}

type connector struct {
	sync.Mutex
	conn      net.Conn
	requestID uint64

	// TODO(kormat): Move the caches to `service`, so they can be shared across connectors.
	asInfos  *cache.Cache
	ifInfos  *cache.Cache
	svcInfos *cache.Cache
}

func connect(socketName string) (*connector, error) {
	return connectTimeout(socketName, time.Duration(-1))
}

func connectTimeout(socketName string, timeout time.Duration) (*connector, error) {
	conn, err := reliable.DialTimeout(socketName, timeout)
	if err != nil {
		return nil, err
	}
	rand.Seed(time.Now().UnixNano())
	c := &connector{conn: conn, requestID: uint64(rand.Uint32())}

	cleanupInterval := time.Minute
	c.asInfos = cache.New(ASInfoTTL, cleanupInterval)
	c.ifInfos = cache.New(IFInfoTTL, cleanupInterval)
	c.svcInfos = cache.New(SVCInfoTTL, cleanupInterval)
	return c, nil
}

// Self incrementing atomic counter for request IDs
func (c *connector) nextID() uint64 {
	return atomic.AddUint64(&c.requestID, 1)
}

func (c *connector) send(p *Pld) error {
	raw, err := proto.PackRoot(p)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(raw)
	return err
}

func (c *connector) receive() (*Pld, error) {
	p := &Pld{}
	err := proto.ParseFromReader(p, proto.SCIONDMsg_TypeID, c.conn)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (c *connector) Paths(dst, src addr.IA, max uint16, f PathReqFlags) (*PathReply, error) {
	c.Lock()
	defer c.Unlock()

	request := &Pld{Id: c.nextID(), Which: proto.SCIONDMsg_Which_pathReq}
	request.PathReq.Dst = dst.IAInt()
	request.PathReq.Src = src.IAInt()
	request.PathReq.MaxPaths = max
	request.PathReq.Flags = f

	err := c.send(request)
	if err != nil {
		return nil, err
	}
	reply, err := c.receive()
	if err != nil {
		return nil, err
	}

	return &reply.PathReply, nil
}

func (c *connector) ASInfo(ia addr.IA) (*ASInfoReply, error) {
	c.Lock()
	defer c.Unlock()

	// Check if information for this ISD-AS is cached
	key := ia.String()
	if value, found := c.asInfos.Get(key); found {
		return value.(*ASInfoReply), nil
	}

	// Value not in cache, so we ask SCIOND
	request := &Pld{Id: c.nextID(), Which: proto.SCIONDMsg_Which_asInfoReq}
	request.AsInfoReq.Isdas = ia.IAInt()
	err := c.send(request)
	if err != nil {
		return nil, err
	}
	reply, err := c.receive()
	if err != nil {
		return nil, err
	}

	// Cache result
	c.asInfos.SetDefault(key, &reply.AsInfoReply)
	return &reply.AsInfoReply, nil
}

func (c *connector) IFInfo(ifs []uint64) (*IFInfoReply, error) {
	c.Lock()
	defer c.Unlock()

	// Store uncached interface IDs
	uncachedIfs := make([]uint64, 0, len(ifs))
	cachedEntries := make([]IFInfoReplyEntry, 0, len(ifs))
	for _, iface := range ifs {
		key := strconv.FormatUint(iface, 10)
		if value, found := c.ifInfos.Get(key); found {
			cachedEntries = append(cachedEntries, value.(IFInfoReplyEntry))
		} else {
			uncachedIfs = append(uncachedIfs, iface)
		}
	}

	if len(uncachedIfs) == 0 && len(ifs) != 0 {
		return &IFInfoReply{RawEntries: cachedEntries}, nil
	}

	// Some values were not in the cache, so we ask SCIOND for them
	request := &Pld{Id: c.nextID(), Which: proto.SCIONDMsg_Which_ifInfoRequest}
	request.IfInfoRequest.IfIDs = uncachedIfs
	err := c.send(request)
	if err != nil {
		return nil, err
	}
	reply, err := c.receive()
	if err != nil {
		return nil, err
	}

	// Add new information to cache
	// If SCIOND does not find HostInfo for a requested IFID, the
	// null answer is not added to the cache.
	for _, entry := range reply.IfInfoReply.RawEntries {
		key := strconv.FormatUint(entry.IfID, 10)
		c.ifInfos.SetDefault(key, entry)
	}

	// Append old cached entries to our reply
	reply.IfInfoReply.RawEntries = append(reply.IfInfoReply.RawEntries, cachedEntries...)
	return &reply.IfInfoReply, nil
}

func (c *connector) SVCInfo(svcTypes []ServiceType) (*ServiceInfoReply, error) {
	c.Lock()
	defer c.Unlock()

	// Store uncached SVC Types
	uncachedSVCs := make([]ServiceType, 0, len(svcTypes))
	cachedEntries := make([]ServiceInfoReplyEntry, 0, len(svcTypes))
	for _, svcType := range svcTypes {
		key := strconv.FormatUint(uint64(svcType), 10)
		if value, found := c.svcInfos.Get(key); found {
			cachedEntries = append(cachedEntries, value.(ServiceInfoReplyEntry))
		} else {
			uncachedSVCs = append(uncachedSVCs, svcType)
		}
	}

	if len(uncachedSVCs) == 0 && len(svcTypes) != 0 {
		return &ServiceInfoReply{Entries: cachedEntries}, nil
	}

	// Some values were not in the cache, so we ask SCIOND for them
	request := &Pld{Id: c.nextID(), Which: proto.SCIONDMsg_Which_serviceInfoRequest}
	request.ServiceInfoRequest.ServiceTypes = uncachedSVCs
	err := c.send(request)
	if err != nil {
		return nil, err
	}
	reply, err := c.receive()
	if err != nil {
		return nil, err
	}

	// Add new information to cache
	for _, entry := range reply.ServiceInfoReply.Entries {
		key := strconv.FormatUint(uint64(entry.ServiceType), 10)
		c.svcInfos.SetDefault(key, entry)
	}

	reply.ServiceInfoReply.Entries = append(reply.ServiceInfoReply.Entries, cachedEntries...)
	return &reply.ServiceInfoReply, nil
}

func (c *connector) RevNotificationFromRaw(revInfo []byte) (*RevReply, error) {
	// Extract information from notification
	ri, err := path_mgmt.NewRevInfoFromRaw(revInfo)
	if err != nil {
		return nil, err
	}
	return c.RevNotification(ri)
}

func (c *connector) RevNotification(revInfo *path_mgmt.RevInfo) (*RevReply, error) {
	c.Lock()
	defer c.Unlock()

	// Encapsulate RevInfo item in RevNotification object
	request := &Pld{Id: c.nextID(), Which: proto.SCIONDMsg_Which_revNotification}
	request.RevNotification.RevInfo = revInfo

	err := c.send(request)
	if err != nil {
		return nil, err
	}
	reply, err := c.receive()
	if err != nil {
		return nil, err
	}

	return &reply.RevReply, nil
}

func (c *connector) Close() error {
	return c.conn.Close()
}

func (c *connector) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
