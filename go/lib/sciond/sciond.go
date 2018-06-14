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
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/proto"
)

// Time to live for cache entries
const (
	ASInfoTTL  = time.Hour
	IFInfoTTL  = time.Hour
	SVCInfoTTL = 10 * time.Second
	// DefaultSCIONDPath contains the system default for a SCIOND socket.
	DefaultSCIONDPath = "/run/shm/sciond/default.sock"
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
	IFInfo(ifs []common.IFIDType) (*IFInfoReply, error)
	// SVCInfo requests from SCIOND information about addresses and ports of
	// infrastructure services.  Slice svcTypes contains a list of desired
	// service types. If unset, a fresh (i.e., uncached) answer containing all
	// service types is returned.
	SVCInfo(svcTypes []ServiceType) (*ServiceInfoReply, error)
	// RevNotification sends a raw revocation to SCIOND, as contained in an
	// SCMP message.
	RevNotificationFromRaw(b []byte) (*RevReply, error)
	// RevNotification sends a RevocationInfo message to SCIOND.
	RevNotification(sRevInfo *path_mgmt.SignedRevInfo) (*RevReply, error)
	// Close shuts down the connection to a SCIOND server.
	Close() error
}

type connector struct {
	sync.Mutex
	dispatcher *disp.Dispatcher
	requestID  uint64

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

	return &connector{
		dispatcher: disp.New(
			transport.NewPacketTransport(conn),
			&Adapter{},
			log.Root(),
		),
		asInfos:  cache.New(ASInfoTTL, time.Minute),
		ifInfos:  cache.New(IFInfoTTL, time.Minute),
		svcInfos: cache.New(SVCInfoTTL, time.Minute),
	}, nil
}

// Self incrementing atomic counter for request IDs
func (c *connector) nextID() uint64 {
	return atomic.AddUint64(&c.requestID, 1)
}

func (c *connector) Paths(dst, src addr.IA, max uint16, f PathReqFlags) (*PathReply, error) {
	c.Lock()
	defer c.Unlock()

	reply, err := c.dispatcher.Request(
		context.Background(),
		&Pld{
			Id:    c.nextID(),
			Which: proto.SCIONDMsg_Which_pathReq,
			PathReq: PathReq{
				Dst:      dst.IAInt(),
				Src:      src.IAInt(),
				MaxPaths: max,
				Flags:    f,
			},
		},
		reliable.NilAppAddr,
	)
	if err != nil {
		return nil, err
	}
	return &reply.(*Pld).PathReply, nil
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
	pld, err := c.dispatcher.Request(
		context.Background(),
		&Pld{
			Id:    c.nextID(),
			Which: proto.SCIONDMsg_Which_asInfoReq,
			AsInfoReq: ASInfoReq{
				Isdas: ia.IAInt(),
			},
		},
		reliable.NilAppAddr,
	)
	if err != nil {
		return nil, err
	}
	asInfoReply := pld.(*Pld).AsInfoReply
	c.asInfos.SetDefault(key, &asInfoReply)
	return &asInfoReply, nil
}

func (c *connector) IFInfo(ifs []common.IFIDType) (*IFInfoReply, error) {
	c.Lock()
	defer c.Unlock()

	// Store uncached interface IDs
	uncachedIfs := make([]common.IFIDType, 0, len(ifs))
	cachedEntries := make([]IFInfoReplyEntry, 0, len(ifs))
	for _, iface := range ifs {
		if value, found := c.ifInfos.Get(iface.String()); found {
			cachedEntries = append(cachedEntries, value.(IFInfoReplyEntry))
		} else {
			uncachedIfs = append(uncachedIfs, iface)
		}
	}

	if len(uncachedIfs) == 0 && len(ifs) != 0 {
		return &IFInfoReply{RawEntries: cachedEntries}, nil
	}

	// Some values were not in the cache, so we ask SCIOND for them
	pld, err := c.dispatcher.Request(
		context.Background(),
		&Pld{
			Id:    c.nextID(),
			Which: proto.SCIONDMsg_Which_ifInfoRequest,
			IfInfoRequest: IFInfoRequest{
				IfIDs: uncachedIfs,
			},
		},
		reliable.NilAppAddr,
	)
	if err != nil {
		return nil, err
	}
	ifInfoReply := pld.(*Pld).IfInfoReply

	// Add new information to cache
	// If SCIOND does not find HostInfo for a requested IFID, the
	// null answer is not added to the cache.
	for _, entry := range ifInfoReply.RawEntries {
		c.ifInfos.SetDefault(entry.IfID.String(), entry)
	}

	// Append old cached entries to our reply
	ifInfoReply.RawEntries = append(ifInfoReply.RawEntries, cachedEntries...)
	return &ifInfoReply, nil
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
	pld, err := c.dispatcher.Request(
		context.Background(),
		&Pld{
			Id:    c.nextID(),
			Which: proto.SCIONDMsg_Which_serviceInfoRequest,
			ServiceInfoRequest: ServiceInfoRequest{
				ServiceTypes: uncachedSVCs,
			},
		},
		reliable.NilAppAddr,
	)
	if err != nil {
		return nil, err
	}
	serviceInfoReply := pld.(*Pld).ServiceInfoReply

	// Add new information to cache
	for _, entry := range serviceInfoReply.Entries {
		key := strconv.FormatUint(uint64(entry.ServiceType), 10)
		c.svcInfos.SetDefault(key, entry)
	}

	serviceInfoReply.Entries = append(serviceInfoReply.Entries, cachedEntries...)
	return &serviceInfoReply, nil
}

func (c *connector) RevNotificationFromRaw(b []byte) (*RevReply, error) {
	// Extract information from notification
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(b)
	if err != nil {
		return nil, err
	}
	return c.RevNotification(sRevInfo)
}

func (c *connector) RevNotification(sRevInfo *path_mgmt.SignedRevInfo) (*RevReply, error) {
	c.Lock()
	defer c.Unlock()

	// Encapsulate RevInfo item in RevNotification object
	reply, err := c.dispatcher.Request(
		context.Background(),
		&Pld{
			Id:    c.nextID(),
			Which: proto.SCIONDMsg_Which_revNotification,
			RevNotification: RevNotification{
				SRevInfo: sRevInfo,
			},
		},
		reliable.NilAppAddr,
	)
	if err != nil {
		return nil, err
	}

	return &reply.(*Pld).RevReply, nil
}

func (c *connector) Close() error {
	return c.dispatcher.Close(context.Background())
}

// GetDefaultSCIONDPath return default sciond path for a given IA
func GetDefaultSCIONDPath(ia *addr.IA) string {
	if ia == nil || ia.IsZero() {
		return DefaultSCIONDPath
	}
	return fmt.Sprintf("/run/shm/sciond/sd%s.sock", ia.FileFmt(false))
}
