// Copyright 2018 Anapaya Systems
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

package integration

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
)

var _ Integration = (*binaryIntegration)(nil)

type binaryIntegration struct {
	name        string
	cmd         string
	clientArgs  []string
	serverArgs  []string
	logRedirect LogRedirect
}

// NewBinaryIntegration returns an implementation of the Integration interface.
// Start* will run the binary programm with name and use the given arguments for the client/server.
// Use SrcIAReplace and DstIAReplace in arguments as placeholder for the source and destination IAs.
// When starting a client/server the placeholders will be replaced with the actual values.
// The server should output the ReadySignal to Stdout once it is ready to accept clients.
func NewBinaryIntegration(name string, cmd string, clientArgs, serverArgs []string,
	logRedirect LogRedirect) Integration {

	return &binaryIntegration{
		name:        name,
		cmd:         cmd,
		clientArgs:  clientArgs,
		serverArgs:  serverArgs,
		logRedirect: logRedirect,
	}
}

func (bi *binaryIntegration) Name() string {
	return bi.name
}

// StartServer starts a server and blocks until the ReadySignal is received on Stdout.
func (bi *binaryIntegration) StartServer(ctx context.Context, dst addr.IA) (Waiter, error) {
	args := replacePattern(DstIAReplace, dst.String(), bi.serverArgs)
	return startServer(ctx, bi.cmd, args, dst, bi.logRedirect)
}

func (bi *binaryIntegration) StartClient(ctx context.Context, src, dst addr.IA) (Waiter, error) {
	args := replacePattern(SrcIAReplace, src.String(), bi.clientArgs)
	args = replacePattern(DstIAReplace, dst.String(), args)
	args = replacePattern(ServerPortReplace, serverPorts[dst], args)
	return startClient(ctx, bi.cmd, args, src, bi.logRedirect)
}
