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
	"os/exec"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
)

const (
	// SrcIAReplace is a placeholder for the source IA in the arguments.
	SrcIAReplace = "<SRCIA>"
	// DstIAReplace is a placeholder for the destination IA in the arguments.
	DstIAReplace = "<DSTIA>"
)

var _ Integration = (*binaryIntegration)(nil)

type binaryIntegration struct {
	name       string
	clientArgs []string
	serverArgs []string
}

// NewBinaryIntegration returns an implementation of the Integration interface.
// Start* will run the binary programm with name and use the given arguments for the client/server.
// Use SrcIAReplace and DstIAReplace in arguments as placeholder for the source and destination IAs.
// When starting a client/server the placeholders will be replaced with the actual values.
func NewBinaryIntegration(name string, clientArgs, serverArgs []string) Integration {
	return &binaryIntegration{
		name:       name,
		clientArgs: clientArgs,
		serverArgs: serverArgs,
	}
}

func (bi *binaryIntegration) Name() string {
	return bi.name
}

func (bi *binaryIntegration) StartServer(ctx context.Context, dst addr.IA) (Waiter, error) {
	args := replacePattern(DstIAReplace, dst.String(), bi.serverArgs)
	r := &binaryWaiter{
		exec.CommandContext(ctx, bi.name, args...),
	}
	return r, r.Start()
}

func (bi *binaryIntegration) StartClient(ctx context.Context, src, dst addr.IA) (Waiter, error) {
	args := replacePattern(SrcIAReplace, src.String(), bi.clientArgs)
	args = replacePattern(DstIAReplace, dst.String(), args)
	r := &binaryWaiter{
		exec.CommandContext(ctx, bi.name, args...),
	}
	return r, r.Start()
}

func replacePattern(pattern string, replacement string, args []string) []string {
	// first copy
	argsCopy := append([]string(nil), args...)
	for i, arg := range argsCopy {
		if strings.Contains(arg, pattern) {
			argsCopy[i] = strings.Replace(arg, pattern, replacement, -1)
		}
	}
	return argsCopy
}

var _ Waiter = (*binaryWaiter)(nil)

type binaryWaiter struct {
	*exec.Cmd
}
