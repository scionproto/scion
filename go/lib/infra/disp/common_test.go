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

package disp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

// testAdapterT implements MessageAdapter for unit level tests.
type testAdapterT struct{}

var (
	// Singleton instantiation of testAdapterS, so tests do not need to
	// allocate a new one.
	testAdapter testAdapterT
)

func (t testAdapterT) MsgToRaw(msg proto.Cerealizable) (common.RawBytes, error) {
	o := msg.(*customObject)
	return []byte(fmt.Sprintf("%d-%s", o.id, o.str)), nil
}

func (t testAdapterT) RawToMsg(b common.RawBytes) (proto.Cerealizable, error) {
	items := strings.Split(string(b), "-")
	if len(items) != 2 {
		return nil, serrors.New("Bad message")
	}
	id, err := strconv.Atoi(items[0])
	if err != nil {
		return nil, common.NewBasicError("Unable to parse ID", err)
	}
	msg := &customObject{
		id:  id,
		str: items[1],
	}
	return msg, nil
}

func (t testAdapterT) MsgKey(msg proto.Cerealizable) string {
	o := msg.(*customObject)
	return strconv.Itoa(o.id)
}

var _ proto.Cerealizable = (*customObject)(nil)

type customObject struct {
	id  int
	str string
}

func (c *customObject) String() string {
	panic("not implemented")
}

func (c *customObject) ProtoId() proto.ProtoIdType {
	panic("not implemented")
}
