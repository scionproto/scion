// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/lib/infra (interfaces: ASInspector,Messenger,ResponseWriter,TrustStore,Verifier)

// Package mock_infra is a generated GoMock package.
package mock_infra

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	common "github.com/scionproto/scion/go/lib/common"
	ctrl "github.com/scionproto/scion/go/lib/ctrl"
	ack "github.com/scionproto/scion/go/lib/ctrl/ack"
	cert_mgmt "github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	ifid "github.com/scionproto/scion/go/lib/ctrl/ifid"
	path_mgmt "github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	seg "github.com/scionproto/scion/go/lib/ctrl/seg"
	infra "github.com/scionproto/scion/go/lib/infra"
	proto "github.com/scionproto/scion/go/proto"
	net "net"
	reflect "reflect"
)

// MockASInspector is a mock of ASInspector interface
type MockASInspector struct {
	ctrl     *gomock.Controller
	recorder *MockASInspectorMockRecorder
}

// MockASInspectorMockRecorder is the mock recorder for MockASInspector
type MockASInspectorMockRecorder struct {
	mock *MockASInspector
}

// NewMockASInspector creates a new mock instance
func NewMockASInspector(ctrl *gomock.Controller) *MockASInspector {
	mock := &MockASInspector{ctrl: ctrl}
	mock.recorder = &MockASInspectorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockASInspector) EXPECT() *MockASInspectorMockRecorder {
	return m.recorder
}

// ByAttributes mocks base method
func (m *MockASInspector) ByAttributes(arg0 context.Context, arg1 addr.ISD, arg2 infra.ASInspectorOpts) ([]addr.IA, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ByAttributes", arg0, arg1, arg2)
	ret0, _ := ret[0].([]addr.IA)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ByAttributes indicates an expected call of ByAttributes
func (mr *MockASInspectorMockRecorder) ByAttributes(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ByAttributes", reflect.TypeOf((*MockASInspector)(nil).ByAttributes), arg0, arg1, arg2)
}

// HasAttributes mocks base method
func (m *MockASInspector) HasAttributes(arg0 context.Context, arg1 addr.IA, arg2 infra.ASInspectorOpts) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HasAttributes", arg0, arg1, arg2)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HasAttributes indicates an expected call of HasAttributes
func (mr *MockASInspectorMockRecorder) HasAttributes(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HasAttributes", reflect.TypeOf((*MockASInspector)(nil).HasAttributes), arg0, arg1, arg2)
}

// MockMessenger is a mock of Messenger interface
type MockMessenger struct {
	ctrl     *gomock.Controller
	recorder *MockMessengerMockRecorder
}

// MockMessengerMockRecorder is the mock recorder for MockMessenger
type MockMessengerMockRecorder struct {
	mock *MockMessenger
}

// NewMockMessenger creates a new mock instance
func NewMockMessenger(ctrl *gomock.Controller) *MockMessenger {
	mock := &MockMessenger{ctrl: ctrl}
	mock.recorder = &MockMessengerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockMessenger) EXPECT() *MockMessengerMockRecorder {
	return m.recorder
}

// AddHandler mocks base method
func (m *MockMessenger) AddHandler(arg0 infra.MessageType, arg1 infra.Handler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddHandler", arg0, arg1)
}

// AddHandler indicates an expected call of AddHandler
func (mr *MockMessengerMockRecorder) AddHandler(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddHandler", reflect.TypeOf((*MockMessenger)(nil).AddHandler), arg0, arg1)
}

// CloseServer mocks base method
func (m *MockMessenger) CloseServer() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseServer")
	ret0, _ := ret[0].(error)
	return ret0
}

// CloseServer indicates an expected call of CloseServer
func (mr *MockMessengerMockRecorder) CloseServer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseServer", reflect.TypeOf((*MockMessenger)(nil).CloseServer))
}

// GetCertChain mocks base method
func (m *MockMessenger) GetCertChain(arg0 context.Context, arg1 *cert_mgmt.ChainReq, arg2 net.Addr, arg3 uint64) (*cert_mgmt.Chain, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCertChain", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*cert_mgmt.Chain)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCertChain indicates an expected call of GetCertChain
func (mr *MockMessengerMockRecorder) GetCertChain(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCertChain", reflect.TypeOf((*MockMessenger)(nil).GetCertChain), arg0, arg1, arg2, arg3)
}

// GetHPCfgs mocks base method
func (m *MockMessenger) GetHPCfgs(arg0 context.Context, arg1 *path_mgmt.HPCfgReq, arg2 net.Addr, arg3 uint64) (*path_mgmt.HPCfgReply, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetHPCfgs", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*path_mgmt.HPCfgReply)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetHPCfgs indicates an expected call of GetHPCfgs
func (mr *MockMessengerMockRecorder) GetHPCfgs(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHPCfgs", reflect.TypeOf((*MockMessenger)(nil).GetHPCfgs), arg0, arg1, arg2, arg3)
}

// GetHPSegs mocks base method
func (m *MockMessenger) GetHPSegs(arg0 context.Context, arg1 *path_mgmt.HPSegReq, arg2 net.Addr, arg3 uint64) (*path_mgmt.HPSegReply, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetHPSegs", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*path_mgmt.HPSegReply)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetHPSegs indicates an expected call of GetHPSegs
func (mr *MockMessengerMockRecorder) GetHPSegs(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHPSegs", reflect.TypeOf((*MockMessenger)(nil).GetHPSegs), arg0, arg1, arg2, arg3)
}

// GetSegChanges mocks base method
func (m *MockMessenger) GetSegChanges(arg0 context.Context, arg1 *path_mgmt.SegChangesReq, arg2 net.Addr, arg3 uint64) (*path_mgmt.SegChangesReply, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSegChanges", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*path_mgmt.SegChangesReply)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSegChanges indicates an expected call of GetSegChanges
func (mr *MockMessengerMockRecorder) GetSegChanges(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSegChanges", reflect.TypeOf((*MockMessenger)(nil).GetSegChanges), arg0, arg1, arg2, arg3)
}

// GetSegChangesIds mocks base method
func (m *MockMessenger) GetSegChangesIds(arg0 context.Context, arg1 *path_mgmt.SegChangesIdReq, arg2 net.Addr, arg3 uint64) (*path_mgmt.SegChangesIdReply, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSegChangesIds", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*path_mgmt.SegChangesIdReply)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSegChangesIds indicates an expected call of GetSegChangesIds
func (mr *MockMessengerMockRecorder) GetSegChangesIds(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSegChangesIds", reflect.TypeOf((*MockMessenger)(nil).GetSegChangesIds), arg0, arg1, arg2, arg3)
}

// GetSegs mocks base method
func (m *MockMessenger) GetSegs(arg0 context.Context, arg1 *path_mgmt.SegReq, arg2 net.Addr, arg3 uint64) (*path_mgmt.SegReply, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSegs", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*path_mgmt.SegReply)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSegs indicates an expected call of GetSegs
func (mr *MockMessengerMockRecorder) GetSegs(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSegs", reflect.TypeOf((*MockMessenger)(nil).GetSegs), arg0, arg1, arg2, arg3)
}

// GetTRC mocks base method
func (m *MockMessenger) GetTRC(arg0 context.Context, arg1 *cert_mgmt.TRCReq, arg2 net.Addr, arg3 uint64) (*cert_mgmt.TRC, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTRC", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*cert_mgmt.TRC)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTRC indicates an expected call of GetTRC
func (mr *MockMessengerMockRecorder) GetTRC(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTRC", reflect.TypeOf((*MockMessenger)(nil).GetTRC), arg0, arg1, arg2, arg3)
}

// ListenAndServe mocks base method
func (m *MockMessenger) ListenAndServe() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ListenAndServe")
}

// ListenAndServe indicates an expected call of ListenAndServe
func (mr *MockMessengerMockRecorder) ListenAndServe() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListenAndServe", reflect.TypeOf((*MockMessenger)(nil).ListenAndServe))
}

// RequestChainIssue mocks base method
func (m *MockMessenger) RequestChainIssue(arg0 context.Context, arg1 *cert_mgmt.ChainIssReq, arg2 net.Addr, arg3 uint64) (*cert_mgmt.ChainIssRep, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestChainIssue", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*cert_mgmt.ChainIssRep)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RequestChainIssue indicates an expected call of RequestChainIssue
func (mr *MockMessengerMockRecorder) RequestChainIssue(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestChainIssue", reflect.TypeOf((*MockMessenger)(nil).RequestChainIssue), arg0, arg1, arg2, arg3)
}

// SendAck mocks base method
func (m *MockMessenger) SendAck(arg0 context.Context, arg1 *ack.Ack, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendAck", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendAck indicates an expected call of SendAck
func (mr *MockMessengerMockRecorder) SendAck(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendAck", reflect.TypeOf((*MockMessenger)(nil).SendAck), arg0, arg1, arg2, arg3)
}

// SendBeacon mocks base method
func (m *MockMessenger) SendBeacon(arg0 context.Context, arg1 *seg.Beacon, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendBeacon", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendBeacon indicates an expected call of SendBeacon
func (mr *MockMessengerMockRecorder) SendBeacon(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendBeacon", reflect.TypeOf((*MockMessenger)(nil).SendBeacon), arg0, arg1, arg2, arg3)
}

// SendCertChain mocks base method
func (m *MockMessenger) SendCertChain(arg0 context.Context, arg1 *cert_mgmt.Chain, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendCertChain", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendCertChain indicates an expected call of SendCertChain
func (mr *MockMessengerMockRecorder) SendCertChain(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendCertChain", reflect.TypeOf((*MockMessenger)(nil).SendCertChain), arg0, arg1, arg2, arg3)
}

// SendChainIssueReply mocks base method
func (m *MockMessenger) SendChainIssueReply(arg0 context.Context, arg1 *cert_mgmt.ChainIssRep, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendChainIssueReply", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendChainIssueReply indicates an expected call of SendChainIssueReply
func (mr *MockMessengerMockRecorder) SendChainIssueReply(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendChainIssueReply", reflect.TypeOf((*MockMessenger)(nil).SendChainIssueReply), arg0, arg1, arg2, arg3)
}

// SendHPCfgReply mocks base method
func (m *MockMessenger) SendHPCfgReply(arg0 context.Context, arg1 *path_mgmt.HPCfgReply, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendHPCfgReply", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendHPCfgReply indicates an expected call of SendHPCfgReply
func (mr *MockMessengerMockRecorder) SendHPCfgReply(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendHPCfgReply", reflect.TypeOf((*MockMessenger)(nil).SendHPCfgReply), arg0, arg1, arg2, arg3)
}

// SendHPSegReg mocks base method
func (m *MockMessenger) SendHPSegReg(arg0 context.Context, arg1 *path_mgmt.HPSegReg, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendHPSegReg", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendHPSegReg indicates an expected call of SendHPSegReg
func (mr *MockMessengerMockRecorder) SendHPSegReg(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendHPSegReg", reflect.TypeOf((*MockMessenger)(nil).SendHPSegReg), arg0, arg1, arg2, arg3)
}

// SendHPSegReply mocks base method
func (m *MockMessenger) SendHPSegReply(arg0 context.Context, arg1 *path_mgmt.HPSegReply, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendHPSegReply", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendHPSegReply indicates an expected call of SendHPSegReply
func (mr *MockMessengerMockRecorder) SendHPSegReply(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendHPSegReply", reflect.TypeOf((*MockMessenger)(nil).SendHPSegReply), arg0, arg1, arg2, arg3)
}

// SendIfId mocks base method
func (m *MockMessenger) SendIfId(arg0 context.Context, arg1 *ifid.IFID, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendIfId", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendIfId indicates an expected call of SendIfId
func (mr *MockMessengerMockRecorder) SendIfId(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendIfId", reflect.TypeOf((*MockMessenger)(nil).SendIfId), arg0, arg1, arg2, arg3)
}

// SendIfStateInfos mocks base method
func (m *MockMessenger) SendIfStateInfos(arg0 context.Context, arg1 *path_mgmt.IFStateInfos, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendIfStateInfos", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendIfStateInfos indicates an expected call of SendIfStateInfos
func (mr *MockMessengerMockRecorder) SendIfStateInfos(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendIfStateInfos", reflect.TypeOf((*MockMessenger)(nil).SendIfStateInfos), arg0, arg1, arg2, arg3)
}

// SendRev mocks base method
func (m *MockMessenger) SendRev(arg0 context.Context, arg1 *path_mgmt.SignedRevInfo, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendRev", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendRev indicates an expected call of SendRev
func (mr *MockMessengerMockRecorder) SendRev(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendRev", reflect.TypeOf((*MockMessenger)(nil).SendRev), arg0, arg1, arg2, arg3)
}

// SendSegChangesIdReply mocks base method
func (m *MockMessenger) SendSegChangesIdReply(arg0 context.Context, arg1 *path_mgmt.SegChangesIdReply, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendSegChangesIdReply", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendSegChangesIdReply indicates an expected call of SendSegChangesIdReply
func (mr *MockMessengerMockRecorder) SendSegChangesIdReply(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendSegChangesIdReply", reflect.TypeOf((*MockMessenger)(nil).SendSegChangesIdReply), arg0, arg1, arg2, arg3)
}

// SendSegChangesReply mocks base method
func (m *MockMessenger) SendSegChangesReply(arg0 context.Context, arg1 *path_mgmt.SegChangesReply, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendSegChangesReply", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendSegChangesReply indicates an expected call of SendSegChangesReply
func (mr *MockMessengerMockRecorder) SendSegChangesReply(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendSegChangesReply", reflect.TypeOf((*MockMessenger)(nil).SendSegChangesReply), arg0, arg1, arg2, arg3)
}

// SendSegReg mocks base method
func (m *MockMessenger) SendSegReg(arg0 context.Context, arg1 *path_mgmt.SegReg, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendSegReg", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendSegReg indicates an expected call of SendSegReg
func (mr *MockMessengerMockRecorder) SendSegReg(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendSegReg", reflect.TypeOf((*MockMessenger)(nil).SendSegReg), arg0, arg1, arg2, arg3)
}

// SendSegReply mocks base method
func (m *MockMessenger) SendSegReply(arg0 context.Context, arg1 *path_mgmt.SegReply, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendSegReply", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendSegReply indicates an expected call of SendSegReply
func (mr *MockMessengerMockRecorder) SendSegReply(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendSegReply", reflect.TypeOf((*MockMessenger)(nil).SendSegReply), arg0, arg1, arg2, arg3)
}

// SendSegSync mocks base method
func (m *MockMessenger) SendSegSync(arg0 context.Context, arg1 *path_mgmt.SegSync, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendSegSync", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendSegSync indicates an expected call of SendSegSync
func (mr *MockMessengerMockRecorder) SendSegSync(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendSegSync", reflect.TypeOf((*MockMessenger)(nil).SendSegSync), arg0, arg1, arg2, arg3)
}

// SendTRC mocks base method
func (m *MockMessenger) SendTRC(arg0 context.Context, arg1 *cert_mgmt.TRC, arg2 net.Addr, arg3 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendTRC", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendTRC indicates an expected call of SendTRC
func (mr *MockMessengerMockRecorder) SendTRC(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendTRC", reflect.TypeOf((*MockMessenger)(nil).SendTRC), arg0, arg1, arg2, arg3)
}

// UpdateSigner mocks base method
func (m *MockMessenger) UpdateSigner(arg0 infra.Signer, arg1 []infra.MessageType) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdateSigner", arg0, arg1)
}

// UpdateSigner indicates an expected call of UpdateSigner
func (mr *MockMessengerMockRecorder) UpdateSigner(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSigner", reflect.TypeOf((*MockMessenger)(nil).UpdateSigner), arg0, arg1)
}

// UpdateVerifier mocks base method
func (m *MockMessenger) UpdateVerifier(arg0 infra.Verifier) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdateVerifier", arg0)
}

// UpdateVerifier indicates an expected call of UpdateVerifier
func (mr *MockMessengerMockRecorder) UpdateVerifier(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateVerifier", reflect.TypeOf((*MockMessenger)(nil).UpdateVerifier), arg0)
}

// MockResponseWriter is a mock of ResponseWriter interface
type MockResponseWriter struct {
	ctrl     *gomock.Controller
	recorder *MockResponseWriterMockRecorder
}

// MockResponseWriterMockRecorder is the mock recorder for MockResponseWriter
type MockResponseWriterMockRecorder struct {
	mock *MockResponseWriter
}

// NewMockResponseWriter creates a new mock instance
func NewMockResponseWriter(ctrl *gomock.Controller) *MockResponseWriter {
	mock := &MockResponseWriter{ctrl: ctrl}
	mock.recorder = &MockResponseWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockResponseWriter) EXPECT() *MockResponseWriterMockRecorder {
	return m.recorder
}

// SendAckReply mocks base method
func (m *MockResponseWriter) SendAckReply(arg0 context.Context, arg1 *ack.Ack) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendAckReply", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendAckReply indicates an expected call of SendAckReply
func (mr *MockResponseWriterMockRecorder) SendAckReply(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendAckReply", reflect.TypeOf((*MockResponseWriter)(nil).SendAckReply), arg0, arg1)
}

// SendCertChainReply mocks base method
func (m *MockResponseWriter) SendCertChainReply(arg0 context.Context, arg1 *cert_mgmt.Chain) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendCertChainReply", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendCertChainReply indicates an expected call of SendCertChainReply
func (mr *MockResponseWriterMockRecorder) SendCertChainReply(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendCertChainReply", reflect.TypeOf((*MockResponseWriter)(nil).SendCertChainReply), arg0, arg1)
}

// SendChainIssueReply mocks base method
func (m *MockResponseWriter) SendChainIssueReply(arg0 context.Context, arg1 *cert_mgmt.ChainIssRep) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendChainIssueReply", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendChainIssueReply indicates an expected call of SendChainIssueReply
func (mr *MockResponseWriterMockRecorder) SendChainIssueReply(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendChainIssueReply", reflect.TypeOf((*MockResponseWriter)(nil).SendChainIssueReply), arg0, arg1)
}

// SendHPCfgReply mocks base method
func (m *MockResponseWriter) SendHPCfgReply(arg0 context.Context, arg1 *path_mgmt.HPCfgReply) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendHPCfgReply", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendHPCfgReply indicates an expected call of SendHPCfgReply
func (mr *MockResponseWriterMockRecorder) SendHPCfgReply(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendHPCfgReply", reflect.TypeOf((*MockResponseWriter)(nil).SendHPCfgReply), arg0, arg1)
}

// SendHPSegReply mocks base method
func (m *MockResponseWriter) SendHPSegReply(arg0 context.Context, arg1 *path_mgmt.HPSegReply) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendHPSegReply", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendHPSegReply indicates an expected call of SendHPSegReply
func (mr *MockResponseWriterMockRecorder) SendHPSegReply(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendHPSegReply", reflect.TypeOf((*MockResponseWriter)(nil).SendHPSegReply), arg0, arg1)
}

// SendIfStateInfoReply mocks base method
func (m *MockResponseWriter) SendIfStateInfoReply(arg0 context.Context, arg1 *path_mgmt.IFStateInfos) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendIfStateInfoReply", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendIfStateInfoReply indicates an expected call of SendIfStateInfoReply
func (mr *MockResponseWriterMockRecorder) SendIfStateInfoReply(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendIfStateInfoReply", reflect.TypeOf((*MockResponseWriter)(nil).SendIfStateInfoReply), arg0, arg1)
}

// SendSegReply mocks base method
func (m *MockResponseWriter) SendSegReply(arg0 context.Context, arg1 *path_mgmt.SegReply) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendSegReply", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendSegReply indicates an expected call of SendSegReply
func (mr *MockResponseWriterMockRecorder) SendSegReply(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendSegReply", reflect.TypeOf((*MockResponseWriter)(nil).SendSegReply), arg0, arg1)
}

// SendTRCReply mocks base method
func (m *MockResponseWriter) SendTRCReply(arg0 context.Context, arg1 *cert_mgmt.TRC) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendTRCReply", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendTRCReply indicates an expected call of SendTRCReply
func (mr *MockResponseWriterMockRecorder) SendTRCReply(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendTRCReply", reflect.TypeOf((*MockResponseWriter)(nil).SendTRCReply), arg0, arg1)
}

// MockTrustStore is a mock of TrustStore interface
type MockTrustStore struct {
	ctrl     *gomock.Controller
	recorder *MockTrustStoreMockRecorder
}

// MockTrustStoreMockRecorder is the mock recorder for MockTrustStore
type MockTrustStoreMockRecorder struct {
	mock *MockTrustStore
}

// NewMockTrustStore creates a new mock instance
func NewMockTrustStore(ctrl *gomock.Controller) *MockTrustStore {
	mock := &MockTrustStore{ctrl: ctrl}
	mock.recorder = &MockTrustStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockTrustStore) EXPECT() *MockTrustStoreMockRecorder {
	return m.recorder
}

// ByAttributes mocks base method
func (m *MockTrustStore) ByAttributes(arg0 context.Context, arg1 addr.ISD, arg2 infra.ASInspectorOpts) ([]addr.IA, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ByAttributes", arg0, arg1, arg2)
	ret0, _ := ret[0].([]addr.IA)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ByAttributes indicates an expected call of ByAttributes
func (mr *MockTrustStoreMockRecorder) ByAttributes(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ByAttributes", reflect.TypeOf((*MockTrustStore)(nil).ByAttributes), arg0, arg1, arg2)
}

// HasAttributes mocks base method
func (m *MockTrustStore) HasAttributes(arg0 context.Context, arg1 addr.IA, arg2 infra.ASInspectorOpts) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HasAttributes", arg0, arg1, arg2)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HasAttributes indicates an expected call of HasAttributes
func (mr *MockTrustStoreMockRecorder) HasAttributes(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HasAttributes", reflect.TypeOf((*MockTrustStore)(nil).HasAttributes), arg0, arg1, arg2)
}

// NewChainReqHandler mocks base method
func (m *MockTrustStore) NewChainReqHandler(arg0 bool) infra.Handler {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewChainReqHandler", arg0)
	ret0, _ := ret[0].(infra.Handler)
	return ret0
}

// NewChainReqHandler indicates an expected call of NewChainReqHandler
func (mr *MockTrustStoreMockRecorder) NewChainReqHandler(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewChainReqHandler", reflect.TypeOf((*MockTrustStore)(nil).NewChainReqHandler), arg0)
}

// NewSigner mocks base method
func (m *MockTrustStore) NewSigner(arg0 common.RawBytes, arg1 infra.SignerMeta) (infra.Signer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewSigner", arg0, arg1)
	ret0, _ := ret[0].(infra.Signer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewSigner indicates an expected call of NewSigner
func (mr *MockTrustStoreMockRecorder) NewSigner(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewSigner", reflect.TypeOf((*MockTrustStore)(nil).NewSigner), arg0, arg1)
}

// NewTRCReqHandler mocks base method
func (m *MockTrustStore) NewTRCReqHandler(arg0 bool) infra.Handler {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewTRCReqHandler", arg0)
	ret0, _ := ret[0].(infra.Handler)
	return ret0
}

// NewTRCReqHandler indicates an expected call of NewTRCReqHandler
func (mr *MockTrustStoreMockRecorder) NewTRCReqHandler(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewTRCReqHandler", reflect.TypeOf((*MockTrustStore)(nil).NewTRCReqHandler), arg0)
}

// NewVerifier mocks base method
func (m *MockTrustStore) NewVerifier() infra.Verifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewVerifier")
	ret0, _ := ret[0].(infra.Verifier)
	return ret0
}

// NewVerifier indicates an expected call of NewVerifier
func (mr *MockTrustStoreMockRecorder) NewVerifier() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewVerifier", reflect.TypeOf((*MockTrustStore)(nil).NewVerifier))
}

// MockVerifier is a mock of Verifier interface
type MockVerifier struct {
	ctrl     *gomock.Controller
	recorder *MockVerifierMockRecorder
}

// MockVerifierMockRecorder is the mock recorder for MockVerifier
type MockVerifierMockRecorder struct {
	mock *MockVerifier
}

// NewMockVerifier creates a new mock instance
func NewMockVerifier(ctrl *gomock.Controller) *MockVerifier {
	mock := &MockVerifier{ctrl: ctrl}
	mock.recorder = &MockVerifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockVerifier) EXPECT() *MockVerifierMockRecorder {
	return m.recorder
}

// Verify mocks base method
func (m *MockVerifier) Verify(arg0 context.Context, arg1 []byte, arg2 *proto.SignS) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify
func (mr *MockVerifierMockRecorder) Verify(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockVerifier)(nil).Verify), arg0, arg1, arg2)
}

// VerifyPld mocks base method
func (m *MockVerifier) VerifyPld(arg0 context.Context, arg1 *ctrl.SignedPld) (*ctrl.Pld, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyPld", arg0, arg1)
	ret0, _ := ret[0].(*ctrl.Pld)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyPld indicates an expected call of VerifyPld
func (mr *MockVerifierMockRecorder) VerifyPld(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyPld", reflect.TypeOf((*MockVerifier)(nil).VerifyPld), arg0, arg1)
}

// WithIA mocks base method
func (m *MockVerifier) WithIA(arg0 addr.IA) infra.Verifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithIA", arg0)
	ret0, _ := ret[0].(infra.Verifier)
	return ret0
}

// WithIA indicates an expected call of WithIA
func (mr *MockVerifierMockRecorder) WithIA(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithIA", reflect.TypeOf((*MockVerifier)(nil).WithIA), arg0)
}

// WithServer mocks base method
func (m *MockVerifier) WithServer(arg0 net.Addr) infra.Verifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithServer", arg0)
	ret0, _ := ret[0].(infra.Verifier)
	return ret0
}

// WithServer indicates an expected call of WithServer
func (mr *MockVerifierMockRecorder) WithServer(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithServer", reflect.TypeOf((*MockVerifier)(nil).WithServer), arg0)
}

// WithSignatureTimestampRange mocks base method
func (m *MockVerifier) WithSignatureTimestampRange(arg0 infra.SignatureTimestampRange) infra.Verifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithSignatureTimestampRange", arg0)
	ret0, _ := ret[0].(infra.Verifier)
	return ret0
}

// WithSignatureTimestampRange indicates an expected call of WithSignatureTimestampRange
func (mr *MockVerifierMockRecorder) WithSignatureTimestampRange(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithSignatureTimestampRange", reflect.TypeOf((*MockVerifier)(nil).WithSignatureTimestampRange), arg0)
}

// WithSrc mocks base method
func (m *MockVerifier) WithSrc(arg0 ctrl.SignSrcDef) infra.Verifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithSrc", arg0)
	ret0, _ := ret[0].(infra.Verifier)
	return ret0
}

// WithSrc indicates an expected call of WithSrc
func (mr *MockVerifierMockRecorder) WithSrc(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithSrc", reflect.TypeOf((*MockVerifier)(nil).WithSrc), arg0)
}
