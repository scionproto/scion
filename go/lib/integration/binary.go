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
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// ServerPortReplace is a placeholder for the server port in the arguments.
	ServerPortReplace = "<ServerPort>"
	// SrcIAReplace is a placeholder for the source IA in the arguments.
	SrcIAReplace = "<SRCIA>"
	// SrcHostReplace is a placeholder for the source host in the arguments.
	SrcHostReplace = "<SRCHost>"
	// SrcAddrReplace is a placeholder for the source address in the arguments.
	SrcAddrReplace = "<SRCIA>,[<SRCHost>]"
	// DstIAReplace is a placeholder for the destination IA in the arguments.
	DstIAReplace = "<DSTIA>"
	// DstHostReplace is a placeholder for the destination host in the arguments.
	DstHostReplace = "<DSTHost>"
	// DstAddrReplace is a placeholder for the destination address in the arguments.
	DstAddrReplace = "<DSTIA>,[<DSTHost>]"
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

	bi := &binaryIntegration{
		name:        name,
		cmd:         cmd,
		clientArgs:  clientArgs,
		serverArgs:  serverArgs,
		logRedirect: logRedirect,
	}
	return dockerize(bi)
}

func (bi *binaryIntegration) Name() string {
	return bi.name
}

// StartServer starts a server and blocks until the ReadySignal is received on Stdout.
func (bi *binaryIntegration) StartServer(ctx context.Context, dst snet.Addr) (Waiter, error) {
	args := replacePattern(DstIAReplace, dst.IA.String(), bi.serverArgs)
	args = replacePattern(DstHostReplace, dst.Host.L3.String(), args)
	startCtx, cancelF := context.WithTimeout(ctx, StartServerTimeout)
	defer cancelF()
	r := &binaryWaiter{
		exec.CommandContext(ctx, bi.cmd, args...),
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
		signal := fmt.Sprintf("%s%s", ReadySignal, dst.IA)
		init := true
		scanner := bufio.NewScanner(sp)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, portString) {
				serverPorts[dst.IA] = strings.TrimPrefix(line, portString)
			}
			if init && signal == line {
				close(ready)
				init = false
			}
		}
	}()
	go func() {
		defer log.LogPanicAndExit()
		bi.logRedirect("Server", "ServerErr", dst.IA, ep)
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

func (bi *binaryIntegration) StartClient(ctx context.Context, src, dst snet.Addr) (Waiter, error) {
	args := replacePattern(SrcIAReplace, src.IA.String(), bi.clientArgs)
	args = replacePattern(SrcHostReplace, src.Host.L3.String(), args)
	args = replacePattern(DstIAReplace, dst.IA.String(), args)
	args = replacePattern(DstHostReplace, dst.Host.L3.String(), args)
	args = replacePattern(ServerPortReplace, serverPorts[dst.IA], args)
	r := &binaryWaiter{
		exec.CommandContext(ctx, bi.cmd, args...),
	}
	r.Env = os.Environ()
	r.Env = append(r.Env, fmt.Sprintf("%s=1", GoIntegrationEnv))
	ep, err := r.StderrPipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer log.LogPanicAndExit()
		bi.logRedirect("Client", "ClientErr", src.IA, ep)
	}()
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
