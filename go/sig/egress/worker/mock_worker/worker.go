// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/sig/egress/worker (interfaces: SCIONWriter)

// Package mock_worker is a generated GoMock package.
package mock_worker

import (
	gomock "github.com/golang/mock/gomock"
	snet "github.com/scionproto/scion/go/lib/snet"
	reflect "reflect"
)

// MockSCIONWriter is a mock of SCIONWriter interface
type MockSCIONWriter struct {
	ctrl     *gomock.Controller
	recorder *MockSCIONWriterMockRecorder
}

// MockSCIONWriterMockRecorder is the mock recorder for MockSCIONWriter
type MockSCIONWriterMockRecorder struct {
	mock *MockSCIONWriter
}

// NewMockSCIONWriter creates a new mock instance
func NewMockSCIONWriter(ctrl *gomock.Controller) *MockSCIONWriter {
	mock := &MockSCIONWriter{ctrl: ctrl}
	mock.recorder = &MockSCIONWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSCIONWriter) EXPECT() *MockSCIONWriterMockRecorder {
	return m.recorder
}

// WriteToSCION mocks base method
func (m *MockSCIONWriter) WriteToSCION(arg0 []byte, arg1 *snet.Addr) (int, error) {
	ret := m.ctrl.Call(m, "WriteToSCION", arg0, arg1)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WriteToSCION indicates an expected call of WriteToSCION
func (mr *MockSCIONWriterMockRecorder) WriteToSCION(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteToSCION", reflect.TypeOf((*MockSCIONWriter)(nil).WriteToSCION), arg0, arg1)
}
