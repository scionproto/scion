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

package snetproxy

import (
	"github.com/scionproto/scion/go/lib/snet"
)

// IOOperation provides an abstraction around any Conn reads and writes.  Types
// that implement this interface contain the Read/Write arguments and return
// values as fields, thus allowing the reconnection loop to run any I/O
// function without caring what it is.
type IOOperation interface {
	// Runs the I/O operation on conn
	Do(conn snet.Conn) error
	// IsWrite returns true for types implementing write operations
	IsWrite() bool
}

type BaseOperation struct {
	buffer   []byte
	numBytes int
}

type WriteOperation struct {
	BaseOperation
}

func (op *WriteOperation) Do(conn snet.Conn) error {
	n, err := conn.Write(op.buffer)
	op.numBytes = n
	return err
}

func (_ *WriteOperation) IsWrite() bool {
	return true
}

type WriteToOperation struct {
	WriteOperation
	address *snet.Addr
}

func (op *WriteToOperation) Do(conn snet.Conn) error {
	n, err := conn.WriteTo(op.buffer, op.address)
	op.numBytes = n
	return err
}

type WriteToSCIONOperation struct {
	WriteToOperation
}

func (op *WriteToSCIONOperation) Do(conn snet.Conn) error {
	n, err := conn.WriteToSCION(op.buffer, op.address)
	op.numBytes = n
	return err
}

type ReadOperation struct {
	BaseOperation
}

func (op *ReadOperation) Do(conn snet.Conn) error {
	n, err := conn.Read(op.buffer)
	op.numBytes = n
	return err
}

func (_ *ReadOperation) IsWrite() bool {
	return false
}

type ReadFromOperation struct {
	ReadOperation
	address *snet.Addr
}

func (op *ReadFromOperation) Do(conn snet.Conn) error {
	n, address, err := conn.ReadFrom(op.buffer)
	op.numBytes = n
	op.address = address.(*snet.Addr)
	return err
}

type ReadFromSCIONOperation struct {
	ReadFromOperation
}

func (op *ReadFromSCIONOperation) Do(conn snet.Conn) error {
	n, address, err := conn.ReadFromSCION(op.buffer)
	op.numBytes = n
	op.address = address
	return err
}
