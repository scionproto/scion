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
	"os/exec"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/log/logparse"
)

const (
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
)

var _ Integration = (*binaryIntegration)(nil)

type binaryIntegration struct {
	name        string
	clientArgs  []string
	serverArgs  []string
	logRedirect LogRedirect
}

// NewBinaryIntegration returns an implementation of the Integration interface.
// Start* will run the binary programm with name and use the given arguments for the client/server.
// Use SrcIAReplace and DstIAReplace in arguments as placeholder for the source and destination IAs.
// When starting a client/server the placeholders will be replaced with the actual values.
// The server should output the ReadySignal to Stdout once it is ready to accept clients.
func NewBinaryIntegration(name string, clientArgs, serverArgs []string,
	logRedirect LogRedirect) Integration {

	return &binaryIntegration{
		name:        name,
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
	startCtx, cancelF := context.WithTimeout(ctx, StartServerTimeout)
	defer cancelF()
	args := replacePattern(DstIAReplace, dst.String(), bi.serverArgs)
	r := &binaryWaiter{
		exec.CommandContext(ctx, bi.name, args...),
	}
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
			if init && signal == line {
				close(ready)
				init = false
			}
		}
	}()
	go bi.logRedirect("Server", "ServerErr", dst, ep)
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

func (bi *binaryIntegration) StartClient(ctx context.Context, src, dst addr.IA) (Waiter, error) {
	args := replacePattern(SrcIAReplace, src.String(), bi.clientArgs)
	args = replacePattern(DstIAReplace, dst.String(), args)
	r := &binaryWaiter{
		exec.CommandContext(ctx, bi.name, args...),
	}
	r.Env = append(r.Env, fmt.Sprintf("%s=1", GoIntegrationEnv))
	ep, err := r.StderrPipe()
	if err != nil {
		return nil, err
	}
	go bi.logRedirect("Client", "ClientErr", src, ep)
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

var _ Waiter = (*binaryWaiter)(nil)

type binaryWaiter struct {
	*exec.Cmd
}
