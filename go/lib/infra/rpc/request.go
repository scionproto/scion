// Copyright 2019 ETH Zurich
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

package rpc

import (
	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/proto"
)

type Request struct {
	SignedPld *ctrl.SignedPld
	// Address records the network address that sent the request. It will
	// usually be used for logging.
	Address string
}

type Reply struct {
	SignedPld *ctrl.SignedPld
}

func messageToSignedPayload(msg *capnp.Message) (*ctrl.SignedPld, error) {
	root, err := msg.RootPtr()
	if err != nil {
		return nil, err
	}
	signedPld := &ctrl.SignedPld{}
	if err := pogs.Extract(signedPld, proto.SignedCtrlPld_TypeID, root.Struct()); err != nil {
		return nil, err
	}
	return signedPld, nil
}

func signedPldToMessage(signedPld *ctrl.SignedPld) (*capnp.Message, error) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, err
	}
	root, err := proto.NewRootSignedCtrlPld(seg)
	if err != nil {
		return nil, err
	}
	if err := pogs.Insert(proto.SignedCtrlPld_TypeID, root.Struct, signedPld); err != nil {
		return nil, err
	}
	return msg, nil

}
