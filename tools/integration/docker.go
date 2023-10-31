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
	"os"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	dockerCmd = "docker"
)

var (
	// Docker indicates if the tests should be executed in a Docker container
	Docker = flag.Bool("d", false, "Run tests in a docker container")
)

var dockerArgs []string

func initDockerArgs() {
	dockerArgs = []string{"compose", "-f", GenFile("scion-dc.yml"), "exec", "-T",
		"-e", fmt.Sprintf("%s=1", GoIntegrationEnv)}
}

var _ Integration = (*dockerIntegration)(nil)

type dockerIntegration struct {
	*binaryIntegration
}

func dockerize(bi *binaryIntegration) Integration {
	if *Docker {
		return &dockerIntegration{
			binaryIntegration: bi,
		}
	}
	return bi
}

// StartServer starts a server and blocks until the ReadySignal is received on Stdout.
func (di *dockerIntegration) StartServer(ctx context.Context, dst *snet.UDPAddr) (Waiter, error) {
	bi := *di.binaryIntegration
	bi.serverArgs = append(dockerArgs, append([]string{TesterID(dst), bi.cmd}, bi.serverArgs...)...)
	bi.cmd = dockerCmd
	log.Debug(fmt.Sprintf("Starting server for %s in a docker container",
		addr.FormatIA(dst.IA, addr.WithFileSeparator())),
	)
	return bi.StartServer(ctx, dst)
}

func (di *dockerIntegration) StartClient(ctx context.Context,
	src, dst *snet.UDPAddr) (*BinaryWaiter, error) {
	bi := *di.binaryIntegration
	bi.clientArgs = append(dockerArgs, append([]string{TesterID(src), bi.cmd}, bi.clientArgs...)...)
	bi.cmd = dockerCmd
	log.Debug(fmt.Sprintf("Starting client for %s in a docker container",
		addr.FormatIA(src.IA, addr.WithFileSeparator())),
	)
	return bi.StartClient(ctx, src, dst)
}

// TesterID returns the ID of the tester container.
func TesterID(a *snet.UDPAddr) string {
	ia := addr.FormatIA(a.IA, addr.WithFileSeparator())
	envID, ok := os.LookupEnv(fmt.Sprintf("tester_%s", strings.Replace(ia, "-", "_", -1)))
	if !ok {
		return fmt.Sprintf("tester_%s", ia)
	}
	return envID
}
