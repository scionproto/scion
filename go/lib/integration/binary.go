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
	"time"

	"github.com/kormat/fmt15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// ServerPortReplace is a placeholder for the server port in the arguments.
	ServerPortReplace = "<ServerPort>"
	// SrcIAReplace is a placeholder for the source IA in the arguments.
	SrcIAReplace = "<SRCIA>"
	// SrcHostReplace is a placeholder for the source host in the arguments.
	SrcHostReplace = "<SRCHost>"
	// SrcAddrPattern is a placeholder for the source address in the arguments.
	SrcAddrPattern = SrcIAReplace + ",[" + SrcHostReplace + "]"
	// DstIAReplace is a placeholder for the destination IA in the arguments.
	DstIAReplace = "<DSTIA>"
	// DstHostReplace is a placeholder for the destination host in the arguments.
	DstHostReplace = "<DSTHost>"
	// DstAddrPattern is a placeholder for the destination address in the arguments.
	DstAddrPattern = DstIAReplace + ",[" + DstHostReplace + "]"
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
	name       string
	cmd        string
	clientArgs []string
	serverArgs []string
	logDir     string
}

// NewBinaryIntegration returns an implementation of the Integration interface.
// Start* will run the binary programm with name and use the given arguments for the client/server.
// Use SrcIAReplace and DstIAReplace in arguments as placeholder for the source and destination IAs.
// When starting a client/server the placeholders will be replaced with the actual values.
// The server should output the ReadySignal to Stdout once it is ready to accept clients.
func NewBinaryIntegration(name string, cmd string, clientArgs, serverArgs []string) Integration {
	logDir := fmt.Sprintf("logs/%s", name)
	err := os.Mkdir(logDir, os.ModePerm)
	if err != nil && !os.IsExist(err) {
		log.Error("Failed to create log folder for testrun", "dir", name, "err", err)
		return nil
	}
	bi := &binaryIntegration{
		name:       name,
		cmd:        cmd,
		clientArgs: clientArgs,
		serverArgs: serverArgs,
		logDir:     logDir,
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
		bi.writeLog("server", dst.IA.FileFmt(false), dst.IA.FileFmt(false), ep)
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
		bi.writeLog("client", clientId(src, dst), fmt.Sprintf("%s -> %s", src.IA, dst.IA), ep)
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

func (bi *binaryIntegration) writeLog(name, id, startInfo string, ep io.ReadCloser) {
	defer ep.Close()
	f, err := os.OpenFile(fmt.Sprintf("%s/%s_%s.log", bi.logDir, name, id),
		os.O_CREATE|os.O_WRONLY, os.FileMode(0644))
	if err != nil {
		log.Error("Failed to create log file for test run (create)",
			"name", name, "id", id, "err", err)
		return
	}
	defer f.Close()
	// seek to end of file.
	if _, err := f.Seek(0, 2); err != nil {
		log.Error("Failed to create log file for test run (seek)",
			"name", name, "id", id, "err", err)
		return
	}
	w := bufio.NewWriter(f)
	defer w.Flush()
	w.WriteString(fmt.Sprintf("%v Starting %s %s\n",
		time.Now().Format(fmt15.TimeFmt), name, startInfo))
	defer w.WriteString(fmt.Sprintf("%v Finished %s %s\n",
		time.Now().Format(fmt15.TimeFmt), name, startInfo))
	scanner := bufio.NewScanner(ep)
	for scanner.Scan() {
		w.WriteString(fmt.Sprintf("%s\n", scanner.Text()))
	}
}

func clientId(src, dst snet.Addr) string {
	return fmt.Sprintf("%s_%s", src.IA.FileFmt(false), dst.IA.FileFmt(false))
}

var _ Waiter = (*binaryWaiter)(nil)

type binaryWaiter struct {
	*exec.Cmd
}
