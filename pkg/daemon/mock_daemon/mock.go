// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/pkg/daemon (interfaces: Connector)

// Package mock_daemon is a generated GoMock package.
package mock_daemon

import (
	context "context"
	netip "net/netip"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/pkg/addr"
	daemon "github.com/scionproto/scion/pkg/daemon"
	drkey "github.com/scionproto/scion/pkg/drkey"
	snet "github.com/scionproto/scion/pkg/snet"
)

// MockConnector is a mock of Connector interface.
type MockConnector struct {
	ctrl     *gomock.Controller
	recorder *MockConnectorMockRecorder
}

// MockConnectorMockRecorder is the mock recorder for MockConnector.
type MockConnectorMockRecorder struct {
	mock *MockConnector
}

// NewMockConnector creates a new mock instance.
func NewMockConnector(ctrl *gomock.Controller) *MockConnector {
	mock := &MockConnector{ctrl: ctrl}
	mock.recorder = &MockConnectorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConnector) EXPECT() *MockConnectorMockRecorder {
	return m.recorder
}

// ASInfo mocks base method.
func (m *MockConnector) ASInfo(arg0 context.Context, arg1 addr.IA) (daemon.ASInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ASInfo", arg0, arg1)
	ret0, _ := ret[0].(daemon.ASInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ASInfo indicates an expected call of ASInfo.
func (mr *MockConnectorMockRecorder) ASInfo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ASInfo", reflect.TypeOf((*MockConnector)(nil).ASInfo), arg0, arg1)
}

// Close mocks base method.
func (m *MockConnector) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockConnectorMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockConnector)(nil).Close))
}

// DRKeyGetASHostKey mocks base method.
func (m *MockConnector) DRKeyGetASHostKey(arg0 context.Context, arg1 drkey.ASHostMeta) (drkey.ASHostKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DRKeyGetASHostKey", arg0, arg1)
	ret0, _ := ret[0].(drkey.ASHostKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DRKeyGetASHostKey indicates an expected call of DRKeyGetASHostKey.
func (mr *MockConnectorMockRecorder) DRKeyGetASHostKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DRKeyGetASHostKey", reflect.TypeOf((*MockConnector)(nil).DRKeyGetASHostKey), arg0, arg1)
}

// DRKeyGetHostASKey mocks base method.
func (m *MockConnector) DRKeyGetHostASKey(arg0 context.Context, arg1 drkey.HostASMeta) (drkey.HostASKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DRKeyGetHostASKey", arg0, arg1)
	ret0, _ := ret[0].(drkey.HostASKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DRKeyGetHostASKey indicates an expected call of DRKeyGetHostASKey.
func (mr *MockConnectorMockRecorder) DRKeyGetHostASKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DRKeyGetHostASKey", reflect.TypeOf((*MockConnector)(nil).DRKeyGetHostASKey), arg0, arg1)
}

// DRKeyGetHostHostKey mocks base method.
func (m *MockConnector) DRKeyGetHostHostKey(arg0 context.Context, arg1 drkey.HostHostMeta) (drkey.HostHostKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DRKeyGetHostHostKey", arg0, arg1)
	ret0, _ := ret[0].(drkey.HostHostKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DRKeyGetHostHostKey indicates an expected call of DRKeyGetHostHostKey.
func (mr *MockConnectorMockRecorder) DRKeyGetHostHostKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DRKeyGetHostHostKey", reflect.TypeOf((*MockConnector)(nil).DRKeyGetHostHostKey), arg0, arg1)
}

// Interfaces mocks base method.
func (m *MockConnector) Interfaces(arg0 context.Context) (map[uint16]netip.AddrPort, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Interfaces", arg0)
	ret0, _ := ret[0].(map[uint16]netip.AddrPort)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Interfaces indicates an expected call of Interfaces.
func (mr *MockConnectorMockRecorder) Interfaces(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Interfaces", reflect.TypeOf((*MockConnector)(nil).Interfaces), arg0)
}

// LocalIA mocks base method.
func (m *MockConnector) LocalIA(arg0 context.Context) (addr.IA, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LocalIA", arg0)
	ret0, _ := ret[0].(addr.IA)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LocalIA indicates an expected call of LocalIA.
func (mr *MockConnectorMockRecorder) LocalIA(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LocalIA", reflect.TypeOf((*MockConnector)(nil).LocalIA), arg0)
}

// Paths mocks base method.
func (m *MockConnector) Paths(arg0 context.Context, arg1, arg2 addr.IA, arg3 daemon.PathReqFlags) ([]snet.Path, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Paths", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]snet.Path)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Paths indicates an expected call of Paths.
func (mr *MockConnectorMockRecorder) Paths(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Paths", reflect.TypeOf((*MockConnector)(nil).Paths), arg0, arg1, arg2, arg3)
}

// PortRange mocks base method.
func (m *MockConnector) PortRange(arg0 context.Context) (uint16, uint16, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PortRange", arg0)
	ret0, _ := ret[0].(uint16)
	ret1, _ := ret[1].(uint16)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// PortRange indicates an expected call of PortRange.
func (mr *MockConnectorMockRecorder) PortRange(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PortRange", reflect.TypeOf((*MockConnector)(nil).PortRange), arg0)
}

// RevNotification mocks base method.
func (m *MockConnector) RevNotification(arg0 context.Context, arg1 addr.IA, arg2 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RevNotification", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// RevNotification indicates an expected call of RevNotification.
func (mr *MockConnectorMockRecorder) RevNotification(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RevNotification", reflect.TypeOf((*MockConnector)(nil).RevNotification), arg0, arg1, arg2)
}

// SVCInfo mocks base method.
func (m *MockConnector) SVCInfo(arg0 context.Context, arg1 []addr.SVC) (map[addr.SVC][]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SVCInfo", arg0, arg1)
	ret0, _ := ret[0].(map[addr.SVC][]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SVCInfo indicates an expected call of SVCInfo.
func (mr *MockConnectorMockRecorder) SVCInfo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SVCInfo", reflect.TypeOf((*MockConnector)(nil).SVCInfo), arg0, arg1)
}
