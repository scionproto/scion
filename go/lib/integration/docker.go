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
	// container indicates the container name where the test should be executed in
	container = flag.String("c", "", "Docker container name (e.g. tester)")
)

var _ Integration = (*dockerIntegration)(nil)

type dockerIntegration struct {
	cntr string
	*binaryIntegration
}

func dockerize(bi *binaryIntegration) Integration {
	if *container != "" {
		return &dockerIntegration{
			cntr:              *container,
			binaryIntegration: bi,
		}
	}
	return bi
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
