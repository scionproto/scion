// Copyright 2020 Anapaya Systems
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

package renewal

import (
	"context"
	"crypto/x509"
	"io"

	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/pkg/trust"
)

// DB is the database required for renewal operations. Implementations need to
// make sure that the data in this DB is persistent.
type DB interface {
	db.LimitSetter
	io.Closer
	// InsertClientChain inserts a client's certificate chain. If there is already a
	// chain with the same serial number as the AS certificate in the chain,
	// this call must error, except if the content is exactly the same.
	InsertClientChain(context.Context, []*x509.Certificate) (bool, error)
	// ClientChains looks up all client chains that match the query.
	ClientChains(context.Context, trust.ChainQuery) ([][]*x509.Certificate, error)
}
