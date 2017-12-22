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

package trust

import (
	"context"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/api"
)

type Cache struct {
	log log.Logger
}

// NewCache initializes a TRC cache/resolver backed by storage/persistent
// caches passed in as arguments.
func NewCache() *Cache {
	return &Cache{}
}

func (c *Cache) GetTRC(ctx context.Context) {
	panic("not implemented")
}

func (c *Cache) GetCert(ctx context.Context) {
	panic("not implemented")
}

// NewRequest initializes a handler for TRC request data coming from peer.
func (c *Cache) NewTRCReqHandler(data interface{}, peer net.Addr) (infra.Handler, error) {
	trcReq, ok := data.(*cert_mgmt.TRCReq)
	if !ok {
		return nil, common.NewCError("wrong message type, expected cert_mgmt.TRCReq", "msg", data)
	}
	reqObject := &trcReqHandler{
		data:  trcReq,
		peer:  peer,
		cache: c,
		log:   c.log,
	}
	return reqObject, nil
}

// NewChainReqHandler initializes a handler for TRC request data coming from peer.
func (c *Cache) NewChainReqHandler(data interface{}, peer net.Addr) (infra.Handler, error) {
	certReq, ok := data.(*cert_mgmt.ChainReq)
	if !ok {
		return nil, common.NewCError("wrong message type, expected cert_mgmt.ChainReq", "msg", data)
	}
	reqObject := &chainReqHandler{
		data:  certReq,
		peer:  peer,
		cache: c,
		log:   c.log,
	}
	return reqObject, nil
}

var _ infra.Handler = (*trcReqHandler)(nil)

// Includes goroutine-specific state
type trcReqHandler struct {
	data  *cert_mgmt.TRCReq
	cache *Cache
	peer  net.Addr
	log   log.Logger
}

func (r *trcReqHandler) Handle(ctx context.Context) {
	// FIXME(scrye): This is only an example for now, the handler does not
	// process TRC requests.
	v := ctx.Value(api.MessengerContextKey)
	if v == nil {
		r.log.Warn("Unable to service request, no Messenger interface found")
		return
	}
	messenger, ok := v.(*api.Messenger)
	if !ok {
		r.log.Warn("Unable to service request, bad Messenger value found")
		return
	}
	subCtx, cancelF := context.WithTimeout(ctx, 3*time.Second)
	defer cancelF()

	fakeTRC := &cert_mgmt.TRC{RawTRC: common.RawBytes("foobar")}
	if err := messenger.SendTRC(subCtx, fakeTRC, nil); err != nil {
		r.log.Error("Messenger API error", "err", err)
	}
}

var _ infra.Handler = (*chainReqHandler)(nil)

// Includes goroutine-specific state
type chainReqHandler struct {
	data  *cert_mgmt.ChainReq
	cache *Cache
	peer  net.Addr
	log   log.Logger
}

func (r *chainReqHandler) Handle(ctx context.Context) {
	panic("not implemented")
}
