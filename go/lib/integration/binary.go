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

package integration

import (
	"context"
	"os/exec"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
)

const (
	LocalAddrReplace  = "<LOCALADDR>"
	RemoteAddrReplace = "<REMOTEADDR>"
)

var _ Integration = (*BinaryIntegration)(nil)

// BinaryIntegration implements the Integration interface. It can be used to run binary programs.
type BinaryIntegration struct {
	name       string
	clientArgs []string
	serverArgs []string
}

func NewBinaryIntegration(name string, clientArgs, serverArgs []string) *BinaryIntegration {
	return &BinaryIntegration{
		name:       name,
		clientArgs: clientArgs,
		serverArgs: serverArgs,
	}
}

func (bi *BinaryIntegration) Name() string {
	return bi.name
}

func (bi *BinaryIntegration) StartServer(ctx context.Context, local addr.IA) (Runner, error) {

	args := replacePattern(LocalAddrReplace, local.String(), bi.serverArgs)
	r := &BinaryRunner{
		exec.CommandContext(ctx, bi.name, args...),
	}
	return r, r.Start()
}

func (bi *BinaryIntegration) StartClient(ctx context.Context, local, remote addr.IA) (
	Runner, error) {

	args := replacePattern(LocalAddrReplace, local.String(), bi.clientArgs)
	args = replacePattern(RemoteAddrReplace, remote.String(), args)
	r := &BinaryRunner{
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

var _ Runner = (*BinaryRunner)(nil)

type BinaryRunner struct {
	*exec.Cmd
}
