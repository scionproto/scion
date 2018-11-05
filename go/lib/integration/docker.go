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
	"flag"
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
)

const (
	dockerCmd = "./tools/dc"
	dockerArg = "exec_tester"
)

var (
	// Container indicates the container name where the test should be executed in
	Container = flag.String("c", "", "Docker container name (e.g. tester)")
)

var _ Integration = (*dockerIntegration)(nil)

type dockerIntegration struct {
	cntr string
	*binaryIntegration
}

// NewDockerIntegration returns an implementation of the Integration interface.
// Start will execute the command in a running docker container and use the given arguments for
// the client/server.
// Use SrcIAReplace and DstIAReplace in arguments as placeholder for the source and destination IAs.
// When starting a client/server the placeholders will be replaced with the actual values.
// The server should output the ReadySignal to Stdout once it is ready to accept clients.
func NewDockerIntegration(cntr string, binary Integration) Integration {

	return &dockerIntegration{
		cntr:              cntr,
		binaryIntegration: binary.(*binaryIntegration),
	}
}

func (di *dockerIntegration) Name() string {
	return di.binaryIntegration.Name()
}

// StartServer starts a server and blocks until the ReadySignal is received on Stdout.
func (di *dockerIntegration) StartServer(ctx context.Context, dst addr.IA) (Waiter, error) {
	bi := *di.binaryIntegration
	env := fmt.Sprintf("%s=1", GoIntegrationEnv)
	bi.serverArgs = append([]string{dockerArg, di.cntr, env, bi.cmd}, bi.serverArgs...)
	bi.cmd = dockerCmd
	return bi.StartServer(ctx, dst)
}

func (di *dockerIntegration) StartClient(ctx context.Context, src, dst addr.IA) (Waiter, error) {
	bi := *di.binaryIntegration
	bi.clientArgs = append([]string{dockerArg, di.cntr, bi.cmd}, bi.clientArgs...)
	bi.cmd = dockerCmd
	return bi.StartClient(ctx, src, dst)
}
