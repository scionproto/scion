// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/lib/topology (interfaces: Topology)

// Package mock_topology is a generated GoMock package.
package mock_topology

import (
	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	common "github.com/scionproto/scion/go/lib/common"
	snet "github.com/scionproto/scion/go/lib/snet"
	topology "github.com/scionproto/scion/go/lib/topology"
	net "net"
	reflect "reflect"
)

// MockTopology is a mock of Topology interface
type MockTopology struct {
	ctrl     *gomock.Controller
	recorder *MockTopologyMockRecorder
}

// MockTopologyMockRecorder is the mock recorder for MockTopology
type MockTopologyMockRecorder struct {
	mock *MockTopology
}

// NewMockTopology creates a new mock instance
func NewMockTopology(ctrl *gomock.Controller) *MockTopology {
	mock := &MockTopology{ctrl: ctrl}
	mock.recorder = &MockTopologyMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockTopology) EXPECT() *MockTopologyMockRecorder {
	return m.recorder
}

// Anycast mocks base method
func (m *MockTopology) Anycast(arg0 addr.HostSVC) (*net.UDPAddr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Anycast", arg0)
	ret0, _ := ret[0].(*net.UDPAddr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Anycast indicates an expected call of Anycast
func (mr *MockTopologyMockRecorder) Anycast(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Anycast", reflect.TypeOf((*MockTopology)(nil).Anycast), arg0)
}

// BR mocks base method
func (m *MockTopology) BR(arg0 string) (topology.BRInfo, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BR", arg0)
	ret0, _ := ret[0].(topology.BRInfo)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// BR indicates an expected call of BR
func (mr *MockTopologyMockRecorder) BR(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BR", reflect.TypeOf((*MockTopology)(nil).BR), arg0)
}

// BRNames mocks base method
func (m *MockTopology) BRNames() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BRNames")
	ret0, _ := ret[0].([]string)
	return ret0
}

// BRNames indicates an expected call of BRNames
func (mr *MockTopologyMockRecorder) BRNames() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BRNames", reflect.TypeOf((*MockTopology)(nil).BRNames))
}

// CA mocks base method
func (m *MockTopology) CA() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CA")
	ret0, _ := ret[0].(bool)
	return ret0
}

// CA indicates an expected call of CA
func (mr *MockTopologyMockRecorder) CA() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CA", reflect.TypeOf((*MockTopology)(nil).CA))
}

// Core mocks base method
func (m *MockTopology) Core() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Core")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Core indicates an expected call of Core
func (mr *MockTopologyMockRecorder) Core() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Core", reflect.TypeOf((*MockTopology)(nil).Core))
}

// Exists mocks base method
func (m *MockTopology) Exists(arg0 addr.HostSVC, arg1 string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exists", arg0, arg1)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Exists indicates an expected call of Exists
func (mr *MockTopologyMockRecorder) Exists(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exists", reflect.TypeOf((*MockTopology)(nil).Exists), arg0, arg1)
}

// Gateways mocks base method
func (m *MockTopology) Gateways() ([]topology.GatewayInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Gateways")
	ret0, _ := ret[0].([]topology.GatewayInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Gateways indicates an expected call of Gateways
func (mr *MockTopologyMockRecorder) Gateways() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Gateways", reflect.TypeOf((*MockTopology)(nil).Gateways))
}

// IA mocks base method
func (m *MockTopology) IA() addr.IA {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IA")
	ret0, _ := ret[0].(addr.IA)
	return ret0
}

// IA indicates an expected call of IA
func (mr *MockTopologyMockRecorder) IA() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IA", reflect.TypeOf((*MockTopology)(nil).IA))
}

// IFInfoMap mocks base method
func (m *MockTopology) IFInfoMap() topology.IfInfoMap {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IFInfoMap")
	ret0, _ := ret[0].(topology.IfInfoMap)
	return ret0
}

// IFInfoMap indicates an expected call of IFInfoMap
func (mr *MockTopologyMockRecorder) IFInfoMap() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IFInfoMap", reflect.TypeOf((*MockTopology)(nil).IFInfoMap))
}

// InterfaceIDs mocks base method
func (m *MockTopology) InterfaceIDs() []common.IFIDType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InterfaceIDs")
	ret0, _ := ret[0].([]common.IFIDType)
	return ret0
}

// InterfaceIDs indicates an expected call of InterfaceIDs
func (mr *MockTopologyMockRecorder) InterfaceIDs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InterfaceIDs", reflect.TypeOf((*MockTopology)(nil).InterfaceIDs))
}

// MTU mocks base method
func (m *MockTopology) MTU() uint16 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MTU")
	ret0, _ := ret[0].(uint16)
	return ret0
}

// MTU indicates an expected call of MTU
func (mr *MockTopologyMockRecorder) MTU() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MTU", reflect.TypeOf((*MockTopology)(nil).MTU))
}

// MakeHostInfos mocks base method
func (m *MockTopology) MakeHostInfos(arg0 topology.ServiceType) ([]net.UDPAddr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MakeHostInfos", arg0)
	ret0, _ := ret[0].([]net.UDPAddr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// MakeHostInfos indicates an expected call of MakeHostInfos
func (mr *MockTopologyMockRecorder) MakeHostInfos(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MakeHostInfos", reflect.TypeOf((*MockTopology)(nil).MakeHostInfos), arg0)
}

// Multicast mocks base method
func (m *MockTopology) Multicast(arg0 addr.HostSVC) ([]*net.UDPAddr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Multicast", arg0)
	ret0, _ := ret[0].([]*net.UDPAddr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Multicast indicates an expected call of Multicast
func (mr *MockTopologyMockRecorder) Multicast(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Multicast", reflect.TypeOf((*MockTopology)(nil).Multicast), arg0)
}

// PublicAddress mocks base method
func (m *MockTopology) PublicAddress(arg0 addr.HostSVC, arg1 string) *net.UDPAddr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublicAddress", arg0, arg1)
	ret0, _ := ret[0].(*net.UDPAddr)
	return ret0
}

// PublicAddress indicates an expected call of PublicAddress
func (mr *MockTopologyMockRecorder) PublicAddress(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublicAddress", reflect.TypeOf((*MockTopology)(nil).PublicAddress), arg0, arg1)
}

// SBRAddress mocks base method
func (m *MockTopology) SBRAddress(arg0 string) *snet.UDPAddr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SBRAddress", arg0)
	ret0, _ := ret[0].(*snet.UDPAddr)
	return ret0
}

// SBRAddress indicates an expected call of SBRAddress
func (mr *MockTopologyMockRecorder) SBRAddress(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SBRAddress", reflect.TypeOf((*MockTopology)(nil).SBRAddress), arg0)
}

// SVCNames mocks base method
func (m *MockTopology) SVCNames(arg0 addr.HostSVC) topology.ServiceNames {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SVCNames", arg0)
	ret0, _ := ret[0].(topology.ServiceNames)
	return ret0
}

// SVCNames indicates an expected call of SVCNames
func (mr *MockTopologyMockRecorder) SVCNames(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SVCNames", reflect.TypeOf((*MockTopology)(nil).SVCNames), arg0)
}

// UnderlayAnycast mocks base method
func (m *MockTopology) UnderlayAnycast(arg0 addr.HostSVC) (*net.UDPAddr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnderlayAnycast", arg0)
	ret0, _ := ret[0].(*net.UDPAddr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UnderlayAnycast indicates an expected call of UnderlayAnycast
func (mr *MockTopologyMockRecorder) UnderlayAnycast(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnderlayAnycast", reflect.TypeOf((*MockTopology)(nil).UnderlayAnycast), arg0)
}

// UnderlayByName mocks base method
func (m *MockTopology) UnderlayByName(arg0 addr.HostSVC, arg1 string) (*net.UDPAddr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnderlayByName", arg0, arg1)
	ret0, _ := ret[0].(*net.UDPAddr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UnderlayByName indicates an expected call of UnderlayByName
func (mr *MockTopologyMockRecorder) UnderlayByName(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnderlayByName", reflect.TypeOf((*MockTopology)(nil).UnderlayByName), arg0, arg1)
}

// UnderlayMulticast mocks base method
func (m *MockTopology) UnderlayMulticast(arg0 addr.HostSVC) ([]*net.UDPAddr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnderlayMulticast", arg0)
	ret0, _ := ret[0].([]*net.UDPAddr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UnderlayMulticast indicates an expected call of UnderlayMulticast
func (mr *MockTopologyMockRecorder) UnderlayMulticast(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnderlayMulticast", reflect.TypeOf((*MockTopology)(nil).UnderlayMulticast), arg0)
}

// UnderlayNextHop mocks base method
func (m *MockTopology) UnderlayNextHop(arg0 common.IFIDType) (*net.UDPAddr, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnderlayNextHop", arg0)
	ret0, _ := ret[0].(*net.UDPAddr)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// UnderlayNextHop indicates an expected call of UnderlayNextHop
func (mr *MockTopologyMockRecorder) UnderlayNextHop(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnderlayNextHop", reflect.TypeOf((*MockTopology)(nil).UnderlayNextHop), arg0)
}

// UnderlayNextHop2 mocks base method
func (m *MockTopology) UnderlayNextHop2(arg0 common.IFIDType) (*net.UDPAddr, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnderlayNextHop2", arg0)
	ret0, _ := ret[0].(*net.UDPAddr)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// UnderlayNextHop2 indicates an expected call of UnderlayNextHop2
func (mr *MockTopologyMockRecorder) UnderlayNextHop2(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnderlayNextHop2", reflect.TypeOf((*MockTopology)(nil).UnderlayNextHop2), arg0)
}

// Writable mocks base method
func (m *MockTopology) Writable() *topology.RWTopology {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Writable")
	ret0, _ := ret[0].(*topology.RWTopology)
	return ret0
}

// Writable indicates an expected call of Writable
func (mr *MockTopologyMockRecorder) Writable() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Writable", reflect.TypeOf((*MockTopology)(nil).Writable))
}
