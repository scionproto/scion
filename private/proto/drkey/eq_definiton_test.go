// Copyright 2022 ETH Zurich
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

package drkey_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb_cp "github.com/scionproto/scion/pkg/proto/control_plane"
	pb_daemon "github.com/scionproto/scion/pkg/proto/daemon"
)

func TestEqualASHostRequest(t *testing.T) {
	controlFields := (&pb_cp.DRKeyASHostRequest{}).ProtoReflect().Descriptor().Fields()
	daemonFields := (&pb_daemon.DRKeyASHostRequest{}).ProtoReflect().Descriptor().Fields()
	checkEquals(t, controlFields, daemonFields)
}

func TestEqualASHostResponse(t *testing.T) {
	controlFields := (&pb_cp.DRKeyASHostResponse{}).ProtoReflect().Descriptor().Fields()
	daemonFields := (&pb_daemon.DRKeyASHostResponse{}).ProtoReflect().Descriptor().Fields()
	checkEquals(t, controlFields, daemonFields)
}

func TestEqualHostASRequest(t *testing.T) {
	controlFields := (&pb_cp.DRKeyHostASRequest{}).ProtoReflect().Descriptor().Fields()
	daemonFields := (&pb_daemon.DRKeyHostASRequest{}).ProtoReflect().Descriptor().Fields()
	checkEquals(t, controlFields, daemonFields)
}

func TestEqualHostASResponse(t *testing.T) {
	controlFields := (&pb_cp.DRKeyHostASResponse{}).ProtoReflect().Descriptor().Fields()
	daemonFields := (&pb_daemon.DRKeyHostASResponse{}).ProtoReflect().Descriptor().Fields()
	checkEquals(t, controlFields, daemonFields)
}

func TestEqualHostHostRequest(t *testing.T) {
	controlFields := (&pb_cp.DRKeyHostHostRequest{}).ProtoReflect().Descriptor().Fields()
	daemonFields := (&pb_daemon.DRKeyHostHostRequest{}).ProtoReflect().Descriptor().Fields()
	checkEquals(t, controlFields, daemonFields)
}

func TestEqualHostHostResponse(t *testing.T) {
	controlFields := (&pb_cp.DRKeyHostHostResponse{}).ProtoReflect().Descriptor().Fields()
	daemonFields := (&pb_daemon.DRKeyHostHostResponse{}).ProtoReflect().Descriptor().Fields()
	checkEquals(t, controlFields, daemonFields)
}

func checkEquals(t *testing.T, controlFields, daemonFields protoreflect.FieldDescriptors) {
	require.Equal(t, controlFields.Len(), daemonFields.Len())
	for i := 0; i < controlFields.Len(); i++ {
		assert.Equal(t, controlFields.Get(i).Name(),
			daemonFields.Get(i).Name())
		assert.Equal(t, controlFields.Get(i).Cardinality(),
			daemonFields.Get(i).Cardinality())
		assert.Equal(t, controlFields.Get(i).Kind(),
			daemonFields.Get(i).Kind())
		assert.Equal(t, controlFields.Get(i).HasJSONName(),
			daemonFields.Get(i).HasJSONName())
		assert.Equal(t, controlFields.Get(i).TextName(),
			daemonFields.Get(i).TextName())
		assert.Equal(t, controlFields.Get(i).JSONName(),
			daemonFields.Get(i).JSONName())
	}
}
