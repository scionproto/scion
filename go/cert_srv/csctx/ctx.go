// Copyright 2018 ETH Zurich
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

package csctx

import (
	"sync/atomic"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/trust"
)

type Ctx struct {
	// config is the configuration
	Conf *conf.Conf
	// Store is the trust store.
	Store *trust.Store
	// TrustDB is the trust DB.
	TrustDB *trustdb.DB
}

var ctx atomic.Value

// Get returns a pointer to the current context.
func Get() *Ctx {
	c := ctx.Load()
	if c != nil {
		return c.(*Ctx)
	}
	return nil
}

// Set updates the current context.
func Set(c *Ctx) {
	ctx.Store(c)
}
