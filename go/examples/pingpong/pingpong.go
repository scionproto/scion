// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Simple application for SCION connectivity using the snet library.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	sd "github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

const (
	DefaultInterval = 1 * time.Second
	DefaultTimeout  = 2 * time.Second
	MaxPings        = 1 << 16
	ReqMsg          = "ping!" // ReqMsg and ReplyMsg length need to be the same
	ReplyMsg        = "pong!"
	TSLen           = 8
	ModeServer      = "server"
	ModeClient      = "client"

	errorNoError quic.ErrorCode = 0x100
)

var (
	local, remote snet.UDPAddr
	fileData      []byte

	count = flag.Int("count", 0,
		fmt.Sprintf("Number of pings, between 0 and %d; a count of 0 means infinity", MaxPings))
	dispatcher = flag.String("dispatcher", "", "Path to dispatcher socket")
	file       = flag.String("file", "",
		"File containing the data to send, optional to test larger data (only client)")
	id          = flag.String("id", "pingpong", "Element ID")
	interactive = flag.Bool("i", false, "Interactive mode")
	interval    = flag.Duration("interval", DefaultInterval, "time between pings")
	mode        = flag.String("mode", ModeClient, "Run in "+ModeClient+" or "+ModeServer+" mode")
	sciondAddr  = flag.String("sciond", sciond.DefaultSCIONDAddress, "SCIOND address")
	timeout     = flag.Duration("timeout", DefaultTimeout, "Timeout for the ping response")
	verbose     = flag.Bool("v", false, "sets verbose output")
	logConsole  string

	// No way to extract error code from error returned after closing session in quic-go.
	// c.f. https://github.com/lucas-clemente/quic-go/issues/2441
	// Workaround by string comparison with known formated error string.
	errorNoErrorString = fmt.Sprintf("Application error %#x", uint64(errorNoError))
)

func init() {
	flag.Var(&local, "local", "(Mandatory) address to listen on")
	flag.Var(&remote, "remote", "(Mandatory for clients) address to connect to")
	flag.StringVar(&logConsole, "log.console", "info",
		"Console logging level: trace|debug|info|warn|error|crit")
}

func main() {
	os.Setenv("TZ", "UTC")
	validateFlags()
	logCfg := log.Config{Console: log.ConsoleConfig{Level: logConsole}}
	if err := log.Setup(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	defer log.HandlePanic()
	initNetwork()
	switch *mode {
	case ModeClient:
		c := newClient()
		setSignalHandler(c)
		c.run()
	case ModeServer:
		server{}.run()
	}
}

func validateFlags() {
	flag.Parse()
	if *mode != ModeClient && *mode != ModeServer {
		LogFatal("Unknown mode, must be either '" + ModeClient + "' or '" + ModeServer + "'")
	}
	if *mode == ModeClient {
		if remote.Host == nil {
			LogFatal("Missing remote address")
		}
		if remote.Host.Port == 0 {
			LogFatal("Invalid remote port", "remote port", remote.Host.Port)
		}
	}
	if local.Host == nil {
		LogFatal("Missing local address")
	}
	if *count < 0 || *count > MaxPings {
		LogFatal("Invalid count", "min", 0, "max", MaxPings, "actual", *count)
	}
	if *file != "" {
		if *mode == ModeClient {
			var err error
			fileData, err = ioutil.ReadFile(*file)
			if err != nil {
				LogFatal("Could not read data file")
			}
		} else {
			log.Info("file argument is ignored for mode " + ModeServer)
		}
	}
}

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}

func initNetwork() {
	if err := squic.Init("", ""); err != nil {
		LogFatal("Unable to initialize QUIC/SCION", "err", err)
	}
	log.Debug("QUIC/SCION successfully initialized")
}

type message struct {
	PingPong  string
	Data      []byte
	Timestamp int64
}

func requestMsg() *message {
	return &message{
		PingPong: ReqMsg,
		Data:     fileData,
	}
}

func replyMsg(request *message) *message {
	return &message{
		ReplyMsg,
		request.Data,
		request.Timestamp,
	}
}

func (m *message) len() int {
	return len(m.PingPong) + len(m.Data) + 8
}

type quicStream struct {
	qstream quic.Stream
	encoder *gob.Encoder
	decoder *gob.Decoder
}

func newQuicStream(qstream quic.Stream) *quicStream {
	return &quicStream{
		qstream,
		gob.NewEncoder(qstream),
		gob.NewDecoder(qstream),
	}
}

func (qs quicStream) WriteMsg(msg *message) error {
	return qs.encoder.Encode(msg)
}

func (qs quicStream) ReadMsg() (*message, error) {
	var msg message
	err := qs.decoder.Decode(&msg)
	if err != nil {
		return nil, err
	}
	return &msg, err
}

type client struct {
	*quicStream
	qsess quic.Session
}

func newClient() *client {
	return &client{}
}

// run dials to a remote SCION address and repeatedly sends ping messages
// while receiving pong messages. For each successful ping-pong, a message
// with the round trip time is printed.
func (c *client) run() {
	// Needs to happen before Dial, as it will 'copy' the remote to the connection.
	// If remote is not in local AS, we need a path!
	c.setupPath()
	defer c.Close()

	ds := reliable.NewDispatcher(*dispatcher)
	sciondConn, err := sd.NewService(*sciondAddr).Connect(context.Background())
	if err != nil {
		LogFatal("Unable to initialize SCION network", "err", err)
	}
	network := snet.NewNetworkWithPR(local.IA, ds, sd.Querier{
		Connector: sciondConn,
		IA:        local.IA,
	}, sd.RevHandler{Connector: sciondConn})

	// Connect to remote address. Note that currently the SCION library
	// does not support automatic binding to local addresses, so the local
	// IP address needs to be supplied explicitly. When supplied a local
	// port of 0, Dial will assign a random free local port.

	c.qsess, err = squic.Dial(network, local.Host, &remote, addr.SvcNone, nil)
	if err != nil {
		LogFatal("Unable to dial", "err", err)
	}

	qstream, err := c.qsess.OpenStreamSync(context.Background())
	if err != nil {
		LogFatal("quic OpenStream failed", "err", err)
	}
	c.quicStream = newQuicStream(qstream)
	log.Debug("Quic stream opened", "local", &local, "remote", &remote)
	go func() {
		defer log.HandlePanic()
		c.send()
	}()
	c.read()
}

func (c *client) Close() error {
	var err error
	if c.qstream != nil {
		err = c.qstream.Close()
	}
	if err == nil && c.qsess != nil {
		// Note closing the session here is fine since we know that all the traffic went through.
		// If you are not sure that this is the case you should probably not close the session.
		// E.g. if you are just sending something to a server and closing the session immediately
		// it might be that the server does not see the message.
		// See also: https://github.com/lucas-clemente/quic-go/issues/464
		err = c.qsess.CloseWithError(errorNoError, "")
	}
	return err
}

func (c client) setupPath() {
	if !remote.IA.Equal(local.IA) {
		path := choosePath(*interactive)
		if path == nil {
			LogFatal("No paths available to remote destination")
		}
		remote.Path = path.Path()
		remote.NextHop = path.UnderlayNextHop()
	}
}

func (c client) send() {
	for i := 0; i < *count || *count == 0; i++ {
		if i != 0 && *interval != 0 {
			time.Sleep(*interval)
		}

		reqMsg := requestMsg()
		// Send ping message to destination
		before := time.Now()
		reqMsg.Timestamp = before.UnixNano()
		err := c.WriteMsg(reqMsg)
		if err != nil {
			log.Error("Unable to write", "err", err)
			continue
		}
	}
	// After sending the last ping, set a ReadDeadline on the stream
	err := c.qstream.SetReadDeadline(time.Now().Add(*timeout))
	if err != nil {
		LogFatal("SetReadDeadline failed", "err", err)
	}
}

func (c client) read() {
	// Receive pong message (with final timeout)
	for i := 0; i < *count || *count == 0; i++ {
		msg, err := c.ReadMsg()
		after := time.Now()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.Debug("ReadDeadline missed", "err", err)
				// ReadDeadline is only set after we are done writing
				// and we don't want to wait indefinitely for the remaining responses
				break
			}
			log.Error("Unable to read", "err", err)
			continue
		}
		if msg.PingPong != ReplyMsg {
			log.Error("Received wrong pingpong", "expected", ReplyMsg, "actual", msg.PingPong)
		}
		if !bytes.Equal(msg.Data, fileData) {
			log.Error("Received different data than sent.")
			continue
		}
		before := time.Unix(0, int64(msg.Timestamp))
		elapsed := after.Sub(before).Round(time.Microsecond)
		if *verbose {
			fmt.Printf("[%s]\tReceived %d bytes from %v: seq=%d RTT=%s\n",
				before.Format(common.TimeFmt), msg.len(), &remote, i, elapsed)
		} else {
			fmt.Printf("Received %d bytes from %v: seq=%d RTT=%s\n",
				msg.len(), &remote, i, elapsed)
		}
	}
}

type server struct {
}

// run listens on a SCION address and replies to any ping message.
// On any error, the server exits.
func (s server) run() {
	ds := reliable.NewDispatcher(*dispatcher)
	sciondConn, err := sd.NewService(*sciondAddr).Connect(context.Background())
	if err != nil {
		LogFatal("Unable to initialize SCION network", "err", err)
	}
	network := snet.NewNetworkWithPR(local.IA, ds, &sd.Querier{
		Connector: sciondConn,
		IA:        local.IA,
	}, sd.RevHandler{Connector: sciondConn})
	if err != nil {
		LogFatal("Unable to initialize SCION network", "err", err)
	}
	qsock, err := squic.Listen(network, local.Host, addr.SvcNone, nil)
	if err != nil {
		LogFatal("Unable to listen", "err", err)
	}
	if len(os.Getenv(integration.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", qsock.Addr().(*net.UDPAddr).Port)
		fmt.Printf("%s%s\n", integration.ReadySignal, local.IA)
	}
	log.Info("Listening", "local", qsock.Addr())
	for {
		qsess, err := qsock.Accept(context.Background())
		if err != nil {
			log.Error("Unable to accept quic session", "err", err)
			// Accept failing means the socket is unusable.
			break
		}
		log.Info("Quic session accepted", "src", qsess.RemoteAddr())
		go func() {
			defer log.HandlePanic()
			s.handleClient(qsess)
		}()
	}
}

func (s server) handleClient(qsess quic.Session) {
	defer qsess.CloseWithError(errorNoError, "")
	qstream, err := qsess.AcceptStream(context.Background())
	if err != nil {
		log.Error("Unable to accept quic stream", "err", err)
		return
	}
	defer qstream.Close()

	qs := newQuicStream(qstream)
	for {
		// Receive ping message
		msg, err := qs.ReadMsg()
		if err != nil {
			if err == io.EOF || err.Error() == errorNoErrorString {
				log.Info("Quic session ended", "src", qsess.RemoteAddr())
			} else {
				log.Error("Unable to read", "err", err)
			}
			break
		}

		// Send pong message
		replyMsg := replyMsg(msg)
		err = qs.WriteMsg(replyMsg)
		if err != nil {
			log.Error("Unable to write", "err", err)
			break
		}
	}
}

func choosePath(interactive bool) snet.Path {
	var pathIndex uint64

	sdConn, err := sd.NewService(*sciondAddr).Connect(context.Background())
	if err != nil {
		LogFatal("Unable to initialize SCION network", "err", err)
	}
	paths, err := sdConn.Paths(context.Background(), remote.IA, local.IA, sd.PathReqFlags{})
	if err != nil {
		LogFatal("Failed to lookup paths", "err", err)
	}

	if interactive {
		fmt.Printf("Available paths to %v\n", remote.IA)
		for i := range paths {
			fmt.Printf("[%2d] %s\n", i, fmt.Sprintf("%s", paths[i]))
		}
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Printf("Choose path: ")
			pathIndexStr, _ := reader.ReadString('\n')
			var err error
			pathIndex, err = strconv.ParseUint(pathIndexStr[:len(pathIndexStr)-1], 10, 64)
			if err == nil && int(pathIndex) < len(paths) {
				break
			}
			fmt.Fprintf(os.Stderr, "ERROR: Invalid path index, valid indices range: [0, %v]\n",
				len(paths))
		}
	}
	fmt.Printf("Using path:\n  %s\n", fmt.Sprintf("%s", paths[pathIndex]))
	return paths[pathIndex]
}

func setSignalHandler(closer io.Closer) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer log.HandlePanic()
		<-c
		closer.Close()
		os.Exit(1)
	}()
}
