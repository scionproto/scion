// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/pkg/router (interfaces: BatchConn)

// Package mock_router is a generated GoMock package.
package mock_router

import (
	net "net"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	conn "github.com/scionproto/scion/go/lib/underlay/conn"
)

// MockBatchConn is a mock of BatchConn interface.
type MockBatchConn struct {
	ctrl     *gomock.Controller
	recorder *MockBatchConnMockRecorder
}

// MockBatchConnMockRecorder is the mock recorder for MockBatchConn.
type MockBatchConnMockRecorder struct {
	mock *MockBatchConn
}

// NewMockBatchConn creates a new mock instance.
func NewMockBatchConn(ctrl *gomock.Controller) *MockBatchConn {
	mock := &MockBatchConn{ctrl: ctrl}
	mock.recorder = &MockBatchConnMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBatchConn) EXPECT() *MockBatchConnMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockBatchConn) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockBatchConnMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockBatchConn)(nil).Close))
}

// ReadBatch mocks base method.
func (m *MockBatchConn) ReadBatch(arg0 conn.Messages) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadBatch", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadBatch indicates an expected call of ReadBatch.
func (mr *MockBatchConnMockRecorder) ReadBatch(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadBatch", reflect.TypeOf((*MockBatchConn)(nil).ReadBatch), arg0)
}

// WriteBatch mocks base method.
func (m *MockBatchConn) WriteBatch(arg0 conn.Messages) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteBatch", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WriteBatch indicates an expected call of WriteBatch.
func (mr *MockBatchConnMockRecorder) WriteBatch(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteBatch", reflect.TypeOf((*MockBatchConn)(nil).WriteBatch), arg0)
}

// WriteTo mocks base method.
func (m *MockBatchConn) WriteTo(arg0 []byte, arg1 *net.UDPAddr) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteTo", arg0, arg1)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WriteTo indicates an expected call of WriteTo.
func (mr *MockBatchConnMockRecorder) WriteTo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteTo", reflect.TypeOf((*MockBatchConn)(nil).WriteTo), arg0, arg1)
}
