// Copyright 2020 Anapaya Systems
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
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// Cmd represents a single command.
type Cmd struct {
	// Binary is the path to the application binary.
	Binary string
	Args   []string
}

// Template returns a command with the place holder arguments filled in.
func (c Cmd) Template(src, dst *snet.UDPAddr) (Cmd, error) {
	args := replacePattern(SrcIAReplace, src.IA.String(), c.Args)
	args = replacePattern(SrcHostReplace, src.Host.IP.String(), args)
	args = replacePattern(DstIAReplace, dst.IA.String(), args)
	args = replacePattern(DstHostReplace, dst.Host.IP.String(), args)
	args = replacePattern(ServerPortReplace, serverPorts[dst.IA], args)
	if needSCIOND(args) {
		daemonAddr, err := GetSCIONDAddress(GenFile(DaemonAddressesFile), src.IA)
		if err != nil {
			return Cmd{}, serrors.Wrap("unable to determine SCION Daemon address", err)
		}
		args = replacePattern(Daemon, daemonAddr, args)
	}
	return Cmd{Binary: c.Binary, Args: args}, nil
}

func (c Cmd) String() string {
	return fmt.Sprintf("%v %v", c.Binary, strings.Join(c.Args, " "))
}

// RunConfig is used to configure the run.
type RunConfig struct {
	Commands []Cmd
	LogFile  string
	// Tester is the tester container to run the commands in. If it is empty,
	// the commands are run directly, instead of in a tester container.
	Tester string
}

// Run runs the commands of the run config. The caller must ensure that all
// commands are executable when run in a tester container. E.g., for end-to-end
// tests this means the source address is the same for all.
func Run(ctx context.Context, cfg RunConfig) error {
	file, err := os.OpenFile(cfg.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	if cfg.Tester != "" {
		args := append([]string{}, dockerArgs...)
		args = append(args, cfg.Tester, "sh", "-c", joinCmds(cfg.Commands))
		cmd = exec.CommandContext(ctx, "docker", args...)
		log.Debug("Running docker command", "cmd", cmd)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", joinCmds(cfg.Commands))
		cmd.Env = append(os.Environ(), fmt.Sprintf("%s=1", GoIntegrationEnv))
		log.Debug("Running command", "cmd", cmd)
	}
	cmd.Stdout, cmd.Stderr = file, file
	return cmd.Run()
}

// Join joins the commands with the provided operator.
func joinCmds(l []Cmd) string {
	cmds := make([]string, 0, len(l))
	for _, cmd := range l {
		cmds = append(cmds, cmd.String())
	}
	return strings.Join(cmds, " && ")
}
