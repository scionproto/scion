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
// To query a SCIOND server, a connection must be established to one using Connect. The returned
// structure can then be queried for information about Paths, ASes, available SCION
// services and interface IDs of border rotuers.
// 
// API calls return the entire answer of SCIOND.
// Fields prefixed with Raw (e.g., RawErrorCode) contain data in the format received from SCIOND.
// These are rarely useful, and the same fields without the prefix (e.g., ErrorCode) should be used
// instead.
package sciond

import (
	"net"
	"math/rand"
	"time"
	"strconv"
	"sync/atomic"
	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"
	"github.com/patrickmn/go-cache"
	"github.com/netsec-ethz/scion/go/proto"
	"github.com/netsec-ethz/scion/go/lib/sock/reliable"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

// Time to live for cache entries
const (
	ASInfoTTL = time.Hour
	IFInfoTTL = time.Hour
	SVCInfoTTL = 10 * time.Second
)

// A Connector is used to query a local SCIOND server. The Connector maintains an internal
// cache for interface, service and AS information. All Connector methods block until either
// an error occurs, or the method successfully returns.
type Connector struct {
	conn net.Conn
	requestID uint64

	ifInfos *cache.Cache
	svcInfos *cache.Cache
	asInfos *cache.Cache
}

func (c *Connector) nextID() uint64 {
	return atomic.AddUint64(&c.requestID, 1)
}

func (c *Connector) sendRequest(request *SCIONDMsg) error {
	message, arena, _ := capnp.NewMessage(capnp.SingleSegment(nil))
	root, _ := proto.NewRootSCIONDMsg(arena)
	err := pogs.Insert(proto.SCIONDMsg_TypeID, root.Struct, request)
	if err != nil {
		return err
	}

	packedMsg, err := message.MarshalPacked()
	if err != nil {
		return err
	}

	_, err = c.conn.Write(packedMsg)
	if err != nil {
		return err
	}

	return nil
}

func (c *Connector) receiveReply() (*SCIONDMsg, error) {
	reply, err := capnp.NewPackedDecoder(c.conn).Decode()
	if err != nil {
		return nil, common.NewError("err", err)
	}

	rootPtr, err := reply.RootPtr()
	if err != nil {
		return nil, common.NewError("err", err)
	}

	message := new(SCIONDMsg)
	err = pogs.Extract(message, proto.SCIONDMsg_TypeID, rootPtr.Struct())
	if err != nil {
		return nil, common.NewError("err", err)
	}
	return message, nil
}

// Paths requests from SCIOND a set of end to end paths between src and dst. max specifices the
// maximum number of paths returned.
func (c *Connector) Paths(src, dst *addr.ISD_AS, max uint16, flush bool, sibra bool) (*PathReply, error) {
	request := &SCIONDMsg{Id: c.nextID(), Which: proto.SCIONDMsg_Which_pathReq}
	request.PathReq.Dst = dst.Uint32()
	request.PathReq.Src = src.Uint32()
	request.PathReq.MaxPaths = max
	request.PathReq.Flags.Flush = flush
	request.PathReq.Flags.Sibra = sibra

	err := c.sendRequest(request)
	if err != nil {
		return nil, common.NewError("err", err)
	}

	reply, err := c.receiveReply()
	if err != nil {
		return nil, common.NewError("err", err)
	}

	// Expose "pretty" ISD-ASes
	reply.PathReply.prepare()

	return &reply.PathReply, nil
}

// ASInfo requests from SCIOND information about AS ia.
func (c *Connector) ASInfo(ia *addr.ISD_AS) (*ASInfoReply, error) {
	// Check if information for this ISD-AS is cached
	key := ia.String()
	value, found := c.asInfos.Get(key)
	if found {
		return value.(*ASInfoReply), nil
	}

	// Value not in cache, so we ask SCIOND
	request := &SCIONDMsg{Id: c.nextID(), Which: proto.SCIONDMsg_Which_asInfoReq}
	request.AsInfoReq.Isdas = ia.Uint32()
	err := c.sendRequest(request)
	if err != nil {
		return nil, common.NewError("err", err)
	}

	reply, err := c.receiveReply()
	if err != nil {
		return nil, common.NewError("err", err)
	}

	// Expose "pretty" ISD-ASes
	reply.AsInfoReply.prepare()

	// Cache result
	c.asInfos.Set(key, &reply.AsInfoReply, cache.DefaultExpiration)

	return &reply.AsInfoReply, nil
}

// IFInfo requests from SCIOND information about addresses and ports of border routers (BRs).
// Splice ifs contains interface IDs of BRs. If unset, all BRs are
// returned.
func (c *Connector) IFInfo(ifs []uint64) (*IFInfoReply, error) {
	// Store uncached interface IDs
	uncachedIfs := make([]uint64, 0, 128)
	cachedEntries := make([]IFInfoReplyEntry, 0)
	for _, iface := range ifs {
		key := strconv.FormatUint(iface, 10)
		value, found := c.ifInfos.Get(key)
		if found {
			cachedEntries = append(cachedEntries, value.(IFInfoReplyEntry))
		} else {
			uncachedIfs = append(uncachedIfs, iface)
		}
	}

	if len(uncachedIfs) == 0 {
		return &IFInfoReply{Entries: cachedEntries}, nil
	}

	// Some values were not in the cache, so we ask SCIOND for them
	request := &SCIONDMsg{Id: c.nextID(), Which: proto.SCIONDMsg_Which_ifInfoRequest}
	request.IfInfoRequest.IfIDs = append([]uint64(nil), uncachedIfs...)
	err := c.sendRequest(request)
	if err != nil {
		return nil, common.NewError("err", err)
	}

	reply, err := c.receiveReply()
	if err != nil {
		return nil, common.NewError("err", err)
	}
	
	// Add new information to cache
	// If SCIOND does not find HostInfo for a requested IFID, the
	// null answer is not added to the cache.
	for _, entry := range reply.IfInfoReply.Entries {
		key := strconv.FormatUint(entry.IfID, 10)
		c.ifInfos.Set(key, entry, cache.DefaultExpiration)
	}

	// Append old cached entries to our reply
	reply.IfInfoReply.Entries = append(reply.IfInfoReply.Entries, cachedEntries...)

	return &reply.IfInfoReply, nil
}

// SVCInfo requests from SCIOND information about addresses and ports of infrastructure services.
// Splice svcTypes contains a list of desired service types. If unset, all service types are
// returned.
func (c *Connector) SVCInfo(svcTypes []addr.HostSVC) (*ServiceInfoReply, error) {
	request := &SCIONDMsg{Id: c.nextID(), Which: proto.SCIONDMsg_Which_serviceInfoRequest}
	request.ServiceInfoRequest.ServiceTypes = append([]addr.HostSVC(nil), svcTypes...)
	err := c.sendRequest(request)
	if err != nil {
		return nil, common.NewError("err", err)
	}

	reply, err := c.receiveReply()
	if err != nil {
		return nil, common.NewError("err", err)
	}
	return &reply.ServiceInfoReply, nil
}

// Connect connects to a SCIOND server listening on socketName. Future method calls on the
// returned Connector request information from SCIOND. The information is not
// guaranteed to be fresh, as the returned connector caches ASInfo replies for ASInfoTTL time,
// IFInfo replies for IFInfoTTL time and SVCInfo for SVCInfoTTL time.
func Connect(socketName string) (*Connector, error) {
	conn, err := reliable.Dial(socketName)
	if err != nil {
		return nil, err
	}

	c := new(Connector)
	c.conn = conn

	rand.Seed(time.Now().UnixNano())
	c.requestID = rand.Uint64() % (1 << 32)

	cleanupInterval := time.Minute
	c.asInfos = cache.New(ASInfoTTL, cleanupInterval)
	c.ifInfos = cache.New(IFInfoTTL, cleanupInterval)
	c.svcInfos = cache.New(SVCInfoTTL, cleanupInterval)

	return c, nil
}

// Close shuts down the connection to a SCIOND server.
func (c *Connector) Close() error {
	return c.conn.Close()
}
