// Copyright 2020 ETH Zurich, Anapaya Systems
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

package colibri_mgmt_test

import (
	"bytes"
	"testing"

	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/proto"
)

func TestWithoutCtrlPld(t *testing.T) {
	root := &colibri_mgmt.ColibriRequestPayload{
		Which: proto.ColibriRequestPayload_Which_unset,
	}
	buffer, err := root.PackRoot()
	if err != nil {
		t.Fatalf("Error serializing payload: %v", err)
	}
	if len(buffer) != 7 {
		t.Fatalf("Expected 15 bytes, got %d", len(buffer))
	}
	copy, err := colibri_mgmt.NewFromRaw(buffer)
	if err != nil {
		t.Fatalf("Error deserializing buffer: %v", err)
	}
	if copy.Which != root.Which {
		t.Fatalf("Not equal")
	}
	otherBuffer, err := copy.PackRoot()
	if err != nil {
		t.Fatalf("Error serializing payload: %v", err)
	}
	if bytes.Compare(buffer, otherBuffer) != 0 {
		t.Fatalf("Serialized message not equal")
	}
}
