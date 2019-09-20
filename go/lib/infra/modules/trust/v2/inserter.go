// Copyright 2019 Anapaya Systems
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
	"errors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
)

var (
	// ErrValidation indicates a validation error.
	ErrValidation = errors.New("validation error")
	// ErrVerification indicates a verification error.
	ErrVerification = errors.New("verification error")
)

// Inserter inserts and verifies trust material into the database.
type Inserter interface {
	// InsertTRC verifies the signed TRC and inserts it into the database.
	// The previous TRC is queried through the provider function, when necessary.
	InsertTRC(ctx context.Context, decoded DecodedTRC, trcProvider TRCProviderFunc) error
	// InsertChain verifies the signed certificate chain and inserts it into the
	// database. The issuing TRC is queried through the provider function, when
	// necessary.
	InsertChain(ctx context.Context, decoded DecodedChain, trcProvider TRCProviderFunc) error
}

// TRCProviderFunc provides TRCs. It is used to configure the TRC retrival
// method of the inserter.
type TRCProviderFunc func(context.Context, addr.ISD, scrypto.Version) (*trc.TRC, error)
