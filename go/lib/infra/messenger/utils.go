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

package messenger

import (
	"context"

	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

const (
	AckRejectFailedToParse  = "Failed to parse"
	AckRejectFailedToVerify = "Failed to verfiy"
	AckRetryDBError         = "DB Error"
)

// SendAckHelper binds the given arguments and returns a function that is convenient to call.
// This is only to reduce boilerplate code in message handlers.
// Note that ctx should have a logger attached.
func SendAckHelper(ctx context.Context, rw infra.ResponseWriter) func(proto.Ack_ErrCode, string) {
	logger := log.FromCtx(ctx)
	return func(errCode proto.Ack_ErrCode, errDesc string) {
		a := &ack.Ack{
			Err:     errCode,
			ErrDesc: errDesc,
		}
		if err := rw.SendAckReply(ctx, a); err != nil {
			logger.Error("Failed to send ack", "err", err)
		}
	}
}
