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

package sciond

import (
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

var _ Service = (*MockService)(nil)

// MockService represents a mock SCIOND service for use in testing, backed by
// an undirected multigraph. Connectors returned by method Connect will respond
// to Paths queries by exploring the graph. The graph does not care about AS
// types, so any connected sequence of ASes is a valid path. The shortest path
// is always returned. If multiple shortest paths exist, they are all returned.
// Cycles are not allowed in returned paths.
//
// Revocations are supported. The mock considers all revocations valid without
// checking, and revoking an IFID results in its corresponding edge being
// deleted from the graph.
//
// The graph is concurrency safe, so it is also possible to directly add or
// delete edges as the test is running (e.g., to manually force path changes or
// revocations).
//
// For an example, see go/lib/pathmgr/pathmgr_test.go.
type MockService struct {
	g *graph.Graph
}

// NewMockService returns a mock SCIOND service on top of a SCION network
// graph.
func NewMockService(g *graph.Graph) *MockService {
	return &MockService{g: g}
}

func (m *MockService) Connect() (Connector, error) {
	return &MockConn{g: m.g}, nil
}

func (m *MockService) ConnectTimeout(timeout time.Duration) (Connector, error) {
	panic("not implemented")
}

var _ Connector = (*MockConn)(nil)

// MockConn represents a mock SCIOND Connector. See the documentation of
// MockService for more information about how to use MockConn. MockConn is safe
// for use from multiple goroutines.
type MockConn struct {
	g    *graph.Graph
	lock sync.Mutex
}

// Paths returns the minimum-length paths from src to dst. If no path exists,
// the error code in the PathReply is set to ErrorNoPaths. If more than one
// minimum-length path exists, all minimum-length paths are returned.
//
// Paths does not guarantee to represent a consistent snapshot of the SCION
// network if the backing multigraph is modified while Paths is running.
func (m *MockConn) Paths(dst, src addr.IA, max uint16, f PathReqFlags) (*PathReply, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	paths := m.g.GetPaths(src.String(), dst.String())
	var entries []PathReplyEntry
	for _, path := range paths {
		var pathInterfaces []PathInterface
		for _, ifid := range path {
			pathInterfaces = append(pathInterfaces,
				PathInterface{
					RawIsdas: m.g.GetParent(ifid).IAInt(),
					IfID:     ifid,
				},
			)
		}
		entries = append(entries,
			PathReplyEntry{
				Path: FwdPathMeta{
					Interfaces: pathInterfaces,
				},
				HostInfo: HostInfo{
				// TODO(scrye): leave nil for now since no tests use this
				},
			},
		)
	}
	if len(entries) == 0 {
		return &PathReply{
			ErrorCode: ErrorNoPaths,
			Entries:   entries,
		}, nil
	}
	return &PathReply{
		ErrorCode: ErrorOk,
		Entries:   entries,
	}, nil
}

// ASInfo is not implemented.
func (m *MockConn) ASInfo(ia addr.IA) (*ASInfoReply, error) {
	panic("not implemented")
}

// IFInfo is not implemented.
func (m *MockConn) IFInfo(ifs []common.IFIDType) (*IFInfoReply, error) {
	panic("not implemented")
}

// SVCInfo is not implemented.
func (m *MockConn) SVCInfo(svcTypes []ServiceType) (*ServiceInfoReply, error) {
	panic("not implemented")
}

// RevNotificationFromRaw is not implemented.
func (m *MockConn) RevNotificationFromRaw(revInfo []byte) (*RevReply, error) {
	panic("not implemented")
}

// RevNotification deletes the edge containing revInfo.IfID from the
// multigraph. RevNotification does not perform any validation of revInfo.
func (m *MockConn) RevNotification(revInfo *path_mgmt.RevInfo) (*RevReply, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.g.RemoveLink(common.IFIDType(revInfo.IfID))
	return &RevReply{
		Result: RevValid,
	}, nil
}

// Close is a no-op.
func (m *MockConn) Close() error {
	return nil
}

// SetDeadline is a no-op.
func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}
