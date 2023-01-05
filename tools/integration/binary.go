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
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	// Daemon is a placeholder for the Daemon server in the arguments.
	Daemon = "<SCIOND>"
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
	// WrapperCmd is the command used to run non-test binaries
	WrapperCmd = "./tools/integration/bin_wrapper.sh"
)

var (
	// FIXME(roosd): The caller to StartServer and StartClient
	// should take care of aggregating the data. I would prefer not to use a
	// global here.
	serverPortsMtx sync.Mutex
	serverPorts    = make(map[addr.IA]string)
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
	logDir := filepath.Join(LogDir(), name)
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
func (bi *binaryIntegration) StartServer(ctx context.Context, dst *snet.UDPAddr) (Waiter, error) {
	args := replacePattern(DstIAReplace, dst.IA.String(), bi.serverArgs)
	args = replacePattern(DstHostReplace, dst.Host.IP.String(), args)
	if needSCIOND(args) {
		daemonAddr, err := GetSCIONDAddress(GenFile(DaemonAddressesFile), dst.IA)
		if err != nil {
			return nil, serrors.WrapStr("unable to determine SCION Daemon address", err)
		}
		args = replacePattern(Daemon, daemonAddr, args)
	}
	r := exec.CommandContext(ctx, bi.cmd, args...)
	log.Info(fmt.Sprintf("%v %v\n", bi.cmd, strings.Join(args, " ")))
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
		defer log.HandlePanic()
		defer sp.Close()
		signal := fmt.Sprintf("%s%s", ReadySignal, dst.IA)
		init := true
		scanner := bufio.NewScanner(sp)
		for scanner.Scan() {
			if scanner.Err() != nil {
				log.Error("Error during reading of stdout", "err", scanner.Err())
				return
			}
			line := scanner.Text()
			if strings.HasPrefix(line, portString) {
				serverPortsMtx.Lock()
				serverPorts[dst.IA] = strings.TrimPrefix(line, portString)
				serverPortsMtx.Unlock()
			}
			if init && signal == line {
				close(ready)
				init = false
			}
		}
	}()
	go func() {
		defer log.HandlePanic()
		ia := addr.FormatIA(dst.IA, addr.WithFileSeparator())
		bi.writeLog("server", ia, ia, ep)
	}()

	if err = r.Start(); err != nil {
		return nil, serrors.WrapStr("Failed to start server", err, "dst", dst.IA)
	}
	select {
	case <-ready:
		return r, err
	case <-time.After(StartServerTimeout):
		return nil, serrors.New("Start server timed out", "dst", dst.IA)
	}
}

func (bi *binaryIntegration) StartClient(ctx context.Context,
	src, dst *snet.UDPAddr) (*BinaryWaiter, error) {

	args := replacePattern(SrcIAReplace, src.IA.String(), bi.clientArgs)
	args = replacePattern(SrcHostReplace, src.Host.IP.String(), args)
	args = replacePattern(DstIAReplace, dst.IA.String(), args)
	args = replacePattern(DstHostReplace, dst.Host.IP.String(), args)
	args = replacePattern(ServerPortReplace, serverPorts[dst.IA], args)
	if needSCIOND(args) {
		daemonAddr, err := GetSCIONDAddress(GenFile(DaemonAddressesFile), src.IA)
		if err != nil {
			return nil, serrors.WrapStr("unable to determine SCION Daemon address", err)
		}
		args = replacePattern(Daemon, daemonAddr, args)
	}
	r := &BinaryWaiter{
		cmd:         exec.CommandContext(ctx, bi.cmd, args...),
		logsWritten: make(chan struct{}),
	}
	log.Info(fmt.Sprintf("%v %v\n", bi.cmd, strings.Join(args, " ")))
	r.cmd.Env = os.Environ()
	r.cmd.Env = append(r.cmd.Env, fmt.Sprintf("%s=1", GoIntegrationEnv))
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, serrors.WrapStr("creating pipe", err)
	}
	r.cmd.Stderr = pw
	r.cmd.Stdout = pw
	defer pw.Close()

	tpr := io.TeeReader(pr, &r.output)

	go func() {
		defer log.HandlePanic()
		defer close(r.logsWritten)
		defer pr.Close()
		bi.writeLog("client", clientID(src, dst), fmt.Sprintf("%s -> %s", src.IA, dst.IA), tpr)
	}()
	return r, r.cmd.Start()
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

func (bi *binaryIntegration) writeLog(name, id, startInfo string, ep io.Reader) {
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
	fmt.Fprintln(w, WithTimestamp(fmt.Sprintf("Starting %s %s", name, startInfo)))
	defer func() {
		fmt.Fprintln(w, WithTimestamp(fmt.Sprintf("Finished %s %s", name, startInfo)))
	}()
	scanner := bufio.NewScanner(ep)
	for scanner.Scan() {
		fmt.Fprintln(w, scanner.Text())
	}
}

func needSCIOND(args []string) bool {
	for _, arg := range args {
		if strings.Contains(arg, Daemon) {
			return true
		}
	}
	return false
}

func clientID(src, dst *snet.UDPAddr) string {
	return fmt.Sprintf("%s_%s",
		addr.FormatIA(src.IA, addr.WithFileSeparator()),
		addr.FormatIA(dst.IA, addr.WithFileSeparator()),
	)
}

// BinaryWaiter can be used to wait on completion of the process.
type BinaryWaiter struct {
	cmd         *exec.Cmd
	logsWritten chan struct{}
	output      bytes.Buffer
}

// Wait waits for completion of the process.
func (bw *BinaryWaiter) Wait() error {
	err := bw.cmd.Wait()
	<-bw.logsWritten
	return err
}

// Output is the output of the process, only available after Wait is returnred.
func (bw *BinaryWaiter) Output() []byte {
	return bw.output.Bytes()
}
