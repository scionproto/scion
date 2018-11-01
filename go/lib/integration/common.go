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
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/log/logparse"
)

const (
	// ServerPortReplace is a placeholder for the server port in the arguments.
	ServerPortReplace = "<ServerPort>"
	// SrcIAReplace is a placeholder for the source IA in the arguments.
	SrcIAReplace = "<SRCIA>"
	// DstIAReplace is a placeholder for the destination IA in the arguments.
	DstIAReplace = "<DSTIA>"
	// ReadySignal should be written to Stdout by the server once it is read to accept clients.
	// The message should always be `Listening ia=<IA>`
	// where <IA> is the IA the server is listening on.
	ReadySignal = "Listening ia="
	// GoIntegrationEnv is an environment variable that is set for the binary under test.
	// It can be used to guard certain statements, like printing the ReadySignal,
	// in a program under test.
	GoIntegrationEnv = "SCION_GO_INTEGRATION"
	// portString is the string a server prints to specify the port it's listening on.
	portString = "Port="
)

var (
	serverPorts = make(map[addr.IA]string)
)

type LogRedirect func(name, pName string, local addr.IA, ep io.ReadCloser)

// StdLog tries to parse any log line from the standard format and logs it with the same log level
// as the original log entry to the log file.
var StdLog LogRedirect = func(name, pName string, local addr.IA, ep io.ReadCloser) {
	defer log.LogPanicAndExit()
	defer ep.Close()
	logparse.ParseFrom(ep, pName, pName, func(e logparse.LogEntry) {
		log.Log(e.Level, fmt.Sprintf("%s@%s: %s", name, local, strings.Join(e.Lines, "\n")))
	})
}

// NonStdLog directly logs any lines as error to the log file
var NonStdLog LogRedirect = func(name, pName string, local addr.IA, ep io.ReadCloser) {
	defer log.LogPanicAndExit()
	defer ep.Close()
	scanner := bufio.NewScanner(ep)
	for scanner.Scan() {
		log.Error(fmt.Sprintf("%s@%s: %s", name, local, scanner.Text()))
	}
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

var _ Waiter = (*waiter)(nil)

type waiter struct {
	*exec.Cmd
}

func startServer(ctx context.Context, cmd string, args []string, dst addr.IA,
	logRedirect LogRedirect) (Waiter, error) {

	startCtx, cancelF := context.WithTimeout(ctx, StartServerTimeout)
	defer cancelF()
	r := &waiter{
		exec.CommandContext(ctx, cmd, args...),
	}
	r.Env = os.Environ()
	r.Env = append(r.Env, fmt.Sprintf("%s=1", GoIntegrationEnv))
	ep, err := r.StderrPipe()
	if err != nil {
		return nil, err
	}
	sp, err := r.StdoutPipe()
	if err != nil {
		return nil, err
	}
	ready := make(chan struct{})
	// parse until we have the ready signal.
	// and then discard the output until the end (required by StdoutPipe).
	go func() {
		defer log.LogPanicAndExit()
		defer sp.Close()
		signal := fmt.Sprintf("%s%s", ReadySignal, dst)
		init := true
		scanner := bufio.NewScanner(sp)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, portString) {
				serverPorts[dst] = strings.TrimPrefix(line, portString)
			}
			if init && signal == line {
				close(ready)
				init = false
			}
		}
	}()
	go func() {
		defer log.LogPanicAndExit()
		logRedirect("Server", "ServerErr", dst, ep)
	}()
	err = r.Start()
	if err != nil {
		return nil, err
	}
	select {
	case <-ready:
		return r, err
	case <-startCtx.Done():
		return nil, startCtx.Err()
	}
}

func startClient(ctx context.Context, cmd string, args []string, src addr.IA,
	logRedirect LogRedirect) (Waiter, error) {

	r := &waiter{
		exec.CommandContext(ctx, cmd, args...),
	}
	r.Env = os.Environ()
	r.Env = append(r.Env, fmt.Sprintf("%s=1", GoIntegrationEnv))
	ep, err := r.StderrPipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer log.LogPanicAndExit()
		logRedirect("Client", "ClientErr", src, ep)
	}()
	return r, r.Start()
}
