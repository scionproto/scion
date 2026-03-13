// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
// Copyright 2023 SCION Association
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

// This is a general purpose client/server code for end2end tests. The client
// sends pings to the server until it receives at least one pong from the
// server or a given deadline is reached. The server responds to all pings and
// the client wait for a response before doing anything else.

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	hummpkg "github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/hummingbird/redemption"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	hummlib "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/metrics"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/keyconf"
	"github.com/scionproto/scion/private/tracing"
	libint "github.com/scionproto/scion/tools/integration"
	integration "github.com/scionproto/scion/tools/integration/integrationlib"
)

const (
	ping              = "ping"
	pong              = "pong"
	hummReservationID = uint32(1)
	hummStartOffset   = -5 * time.Second
)

type Ping struct {
	Server  addr.IA `json:"server"`
	Message string  `json:"message"`
	Trace   []byte  `json:"trace"`
}

type Pong struct {
	Client  addr.IA `json:"client"`
	Server  addr.IA `json:"server"`
	Message string  `json:"message"`
	Trace   []byte  `json:"trace"`
}

var (
	remote                 snet.UDPAddr
	timeout                = &util.DurWrap{Duration: 10 * time.Second}
	scionPacketConnMetrics = metrics.NewSCIONPacketConnMetrics()
	scmpErrorsCounter      = scionPacketConnMetrics.SCMPErrors
	epic                   bool
	hummingbird            string                // e.g. for BW=1, duration=5s do "1,5s"
	hummKeysDir            string                // deleteme for testing purposes only
	hummParams             hummingbirdParameters // derived from the string in hummingbird
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.HandlePanic()
	defer log.Flush()
	addFlags()
	err := integration.Setup()
	if err != nil {
		log.Error("Parsing common flags failed", "err", err)
		return 1
	}
	validateFlags()

	closeTracer, err := integration.InitTracer("end2end-" + integration.Mode)
	if err != nil {
		log.Error("Tracer initialization failed", "err", err)
		return 1
	}
	defer closeTracer()

	if integration.Mode == integration.ModeServer {
		server{}.run()
		return 0
	}
	c := client{}
	return c.run()
}

func addFlags() {
	flag.Var(&remote, "remote", "(Mandatory for clients) address to connect to")
	flag.Var(timeout, "timeout", "The timeout for each attempt")
	flag.BoolVar(&epic, "epic", false, "Enable EPIC")
	flag.StringVar(&hummingbird, "hummingbird", "", "Enable Hummingbird with BW,dur (e.g. '3,5s')")
	flag.StringVar(&hummKeysDir, "hummKeysDir", "",
		"Root directory containing AS*/keys/master0.key files for Hummingbird")
}

func validateFlags() {
	if epic && hummingbird != "" {
		integration.LogFatal("EPIC and Hummingbird modes are mutually exclusive")
	}
	if integration.Mode == integration.ModeClient {
		if remote.Host == nil {
			integration.LogFatal("Missing remote address")
		}
		if remote.Host.Port == 0 {
			integration.LogFatal("Invalid remote port", "remote port", remote.Host.Port)
		}
		if timeout.Duration == 0 {
			integration.LogFatal("Invalid timeout provided", "timeout", timeout)
		}
	}
	if hummingbird != "" {
		// Parse bandwidth and duration.

		re := regexp.MustCompile(`(\d),(.+)`)
		matches := re.FindSubmatch([]byte(hummingbird))
		if len(matches) != 3 {
			integration.LogFatal("bad BW,duration in hummingbird flag")
		}
		bw, err := strconv.ParseUint(string(matches[1]), 10, 16)
		if err != nil {
			integration.LogFatal("bad hummingbird bandwidth",
				"value", string(matches[1]), "err", err)
		}
		dur, err := time.ParseDuration(string(matches[2]))
		if err != nil {
			integration.LogFatal("bad hummingbird duration",
				"value", string(matches[2]), "err", err)
		}
		if dur.Seconds() > math.MaxUint16 {
			integration.LogFatal("hummingbird duration too long. Must fit in 16 bits in seconds",
				"value", dur.Seconds())
		}
		hummParams = hummingbirdParameters{
			Bw:       uint16(bw),
			Duration: uint16(dur.Seconds()),
		}
	}
	log.Info("Flags", "timeout", timeout, "epic", epic, "hummingbird", hummingbird,
		"humm_keys_dir", hummKeysDir, "remote", remote)
}

type server struct{}

func (s server) run() {
	log.Info("Starting server", "isd_as", integration.Local.IA)
	defer log.Info("Finished server", "isd_as", integration.Local.IA)

	sdConn := integration.SDConn()
	defer sdConn.Close()

	loadCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	topo, err := daemon.LoadTopology(loadCtx, sdConn)
	if err != nil {
		integration.LogFatal("Error loading topology", "err", err)
	}

	sn := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		PacketConnMetrics: scionPacketConnMetrics,
		Topology:          topo,
	}
	conn, err := sn.Listen(context.Background(), "udp", integration.Local.Host)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*snet.UDPAddr)
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", localAddr.Host.Port)
		fmt.Printf("%s%s\n\n", libint.ReadySignal, integration.Local.IA)
	}
	log.Info("Listening", "local", fmt.Sprintf("%v:%d", localAddr.Host.IP, localAddr.Host.Port))
	// Receive ping message
	for {
		if err := s.handlePing(conn); err != nil {
			log.Error("Error handling ping", "err", err)
		}
	}
}

func (s server) handlePing(conn *snet.Conn) error {
	rawPld := make([]byte, common.MaxMTU)
	n, clientAddr, err := readFrom(conn, rawPld)
	if err != nil {
		return serrors.Wrap("reading packet", err)
	}

	var pld Ping
	if err := json.Unmarshal(rawPld[:n], &pld); err != nil {
		return serrors.New("invalid payload contents",
			"data", string(rawPld),
		)
	}

	spanCtx, err := opentracing.GlobalTracer().Extract(
		opentracing.Binary,
		bytes.NewReader(pld.Trace),
	)
	if err != nil {
		return serrors.Wrap("extracting trace information", err)
	}
	span, _ := opentracing.StartSpanFromContext(
		context.Background(),
		"handle_ping",
		ext.RPCServerOption(spanCtx),
	)
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}
	clientUDPAddr := clientAddr.(*snet.UDPAddr)
	if pld.Message != ping || !pld.Server.Equal(integration.Local.IA) {
		return withTag(serrors.New("unexpected data in payload",
			"remote", clientUDPAddr,
			"data", pld,
		))
	}
	log.Info(fmt.Sprintf("Ping received from %v, sending pong.", clientUDPAddr))
	raw, err := json.Marshal(Pong{
		Client:  clientUDPAddr.IA,
		Server:  integration.Local.IA,
		Message: pong,
		Trace:   pld.Trace,
	})
	if err != nil {
		return withTag(serrors.Wrap("packing pong", err))
	}
	// Send pong
	if _, err := conn.WriteTo(raw, clientUDPAddr); err != nil {
		return withTag(serrors.Wrap("sending reply", err))
	}
	log.Info("Sent pong to", "client", clientUDPAddr)
	return nil
}

type client struct {
	network *snet.SCIONNetwork
	conn    *snet.Conn
	sdConn  daemon.Connector

	errorPaths map[snet.PathFingerprint]struct{}
	// Specific to Hummingbird:
	useHummingbird bool
	hummKeysDir    string
	hummParams     hummingbirdParameters
	hummSVByIA     map[addr.IA][]byte
}

func (c *client) run() int {
	pair := fmt.Sprintf("%s -> %s", integration.Local.IA, remote.IA)
	log.Info("Starting", "pair", pair)
	defer log.Info("Finished", "pair", pair)
	defer integration.Done(integration.Local.IA, remote.IA)
	c.sdConn = integration.SDConn()
	defer c.sdConn.Close()

	loadCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	topo, err := daemon.LoadTopology(loadCtx, c.sdConn)
	if err != nil {
		integration.LogFatal("Error loading topology", "err", err)
	}

	c.network = &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: c.sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		PacketConnMetrics: scionPacketConnMetrics,
		Topology:          topo,
	}
	c.useHummingbird = hummingbird != ""
	c.hummKeysDir = hummKeysDir
	c.hummParams = hummParams
	c.hummSVByIA = make(map[addr.IA][]byte)
	log.Info("Send", "local",
		fmt.Sprintf("%v,[%v] -> %v,[%v]",
			integration.Local.IA, integration.Local.Host,
			remote.IA, remote.Host))
	c.errorPaths = make(map[snet.PathFingerprint]struct{})
	return integration.AttemptRepeatedly("End2End", c.attemptRequest)
}

// attemptRequest sends one ping packet and expect a pong.
// Returns true (which means "stop") *if both worked*.
func (c *client) attemptRequest(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	span, ctx := tracing.CtxWith(timeoutCtx, "attempt")
	span.SetTag("attempt", n)
	span.SetTag("src", integration.Local.IA)
	span.SetTag("dst", remote.IA)
	defer span.Finish()
	logger := log.FromCtx(ctx)

	path, err := c.getRemote(ctx, n)
	if err != nil {
		logger.Error("Could not get remote", "err", err)
		return false
	}
	if err := c.configureRemotePath(ctx, path); err != nil {
		logger.Error("Could not configure path", "err", err)
		if path != nil {
			c.errorPaths[path.Metadata().Fingerprint()] = struct{}{}
		}
		return false
	}
	span, ctx = tracing.StartSpanFromCtx(ctx, "attempt.ping")
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	// Send ping
	close, err := c.ping(ctx, n, path)
	if err != nil {
		logger.Error("Could not send packet", "err", withTag(err))
		if path != nil {
			c.errorPaths[path.Metadata().Fingerprint()] = struct{}{}
		}
		return false
	}
	defer close()
	// Receive pong
	if err := c.pong(ctx); err != nil {
		logger.Error("Error receiving pong", "err", withTag(err))
		if path != nil {
			c.errorPaths[path.Metadata().Fingerprint()] = struct{}{}
		}
		return false
	}
	return true
}

func (c *client) ping(ctx context.Context, n int, path snet.Path) (func(), error) {
	rawPing, err := json.Marshal(Ping{
		Server:  remote.IA,
		Message: ping,
		Trace:   tracing.IDFromCtx(ctx),
	})
	if err != nil {
		return nil, serrors.Wrap("packing ping", err)
	}
	log.FromCtx(ctx).Info("Dialing", "remote", remote)
	c.conn, err = c.network.Dial(ctx, "udp", integration.Local.Host, &remote)
	if err != nil {
		return nil, serrors.Wrap("dialing conn", err)
	}
	if err := c.conn.SetWriteDeadline(getDeadline(ctx)); err != nil {
		return nil, serrors.Wrap("setting write deadline", err)
	}
	log.Info("sending ping", "attempt", n, "remote", c.conn.RemoteAddr())
	if _, err := c.conn.Write(rawPing); err != nil {
		return nil, err
	}
	closer := func() {
		if err := c.conn.Close(); err != nil {
			log.Error("Unable to close connection", "err", err)
		}
	}
	return closer, nil
}

func (c *client) getRemote(ctx context.Context, n int) (snet.Path, error) {
	if remote.IA.Equal(integration.Local.IA) {
		remote.Path = snetpath.Empty{}
		return nil, nil
	}
	span, ctx := tracing.StartSpanFromCtx(ctx, "attempt.get_remote")
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA,
		daemontypes.PathReqFlags{Refresh: n != 0})
	if err != nil {
		return nil, withTag(serrors.Wrap("requesting paths", err))
	}
	// If all paths had an error, let's try them again.
	if len(paths) <= len(c.errorPaths) {
		c.errorPaths = make(map[snet.PathFingerprint]struct{})
	}
	var path snet.Path
	for _, p := range paths {
		if _, ok := c.errorPaths[p.Metadata().Fingerprint()]; ok {
			continue
		}
		path = p
		break
	}
	if path == nil {
		return nil, withTag(serrors.New("no path found",
			"candidates", len(paths),
			"errors", len(c.errorPaths),
		))
	}
	return path, nil
}

// configureRemotePath sets remote.Path/remote.NextHop for the selected SCION path.
// Depending on flags, it uses the raw SCION dataplane path, wraps it as EPIC,
// or builds a Hummingbird reservation path derived from per-AS keys.
func (c *client) configureRemotePath(ctx context.Context, path snet.Path) error {
	if path == nil {
		remote.Path = snetpath.Empty{}
		remote.NextHop = nil
		return nil
	}

	// Extract forwarding path from the SCION Daemon response.
	// If the epic flag is set, try to use the EPIC path type header.
	if epic {
		scionPath, ok := path.Dataplane().(snetpath.SCION)
		if !ok {
			return serrors.New("provided path must be of type scion")
		}
		epicPath, err := snetpath.NewEPICDataplanePath(scionPath, path.Metadata().EpicAuths)
		if err != nil {
			return err
		}
		remote.Path = epicPath
	} else if c.useHummingbird {
		var reservation *snetpath.Reservation
		var err error
		if c.hummKeysDir != "" {
			reservation, err = c.buildReservationWithSecretValues(ctx, path, time.Now())
		} else {
			reservation, err = c.buildReservationWithRedemptions(ctx, path, time.Now())
		}
		if err != nil {
			return err
		}
		remote.Path = reservation
	} else {
		remote.Path = path.Dataplane()
	}
	remote.NextHop = path.UnderlayNextHop()
	return nil
}

func (c *client) buildReservationWithRedemptions(
	ctx context.Context,
	path snet.Path,
	now time.Time,
) (*snetpath.Reservation, error) {
	returnNow := func() time.Time {
		return now
	}
	// Build a redemption client.
	redemptClient, err := redemption.NewRedemptionClient(ctx, integration.SDConn())
	if err != nil {
		return nil, err
	}
	// Obtain the flyovers.
	flyovers, err := redemptClient.RedeemPathWithRequest(ctx, path, hummpkg.RedemptionRequestNoHop{
		StartTime: util.TimeToSecs(returnNow()),
		Bw:        hummParams.Bw,
		Duration:  hummParams.Duration,
	})
	if err != nil {
		return nil, fmt.Errorf("redeeming flyovers: %w", err)
	}

	// Build a reservation with the flyovers.
	return snetpath.NewReservation(
		snetpath.WithNow(returnNow),
		snetpath.WithScionPath(path, snetpath.FlyoversToMap(flyovers)),
	)
}

func (c *client) buildReservationWithSecretValues(
	ctx context.Context,
	path snet.Path,
	now time.Time,
) (*snetpath.Reservation, error) {
	returnNow := func() time.Time {
		return now
	}
	baseHops := snetpath.InterfacesToBaseHops(path.Metadata().Interfaces)
	flyovers := make([]*snetpath.Hop, 0, len(baseHops))
	startTime := uint32(now.Add(hummStartOffset).Unix())
	aesByIA := make(map[addr.IA]cipher.Block)
	buffer := make([]byte, hummlib.AkBufferSize)

	hummBandwidth := c.hummParams.Bw
	hummDurationSeconds := c.hummParams.Duration
	for _, baseHop := range baseHops {
		block, ok := aesByIA[baseHop.IA]
		if !ok {
			sv, err := c.hummSecretValue(baseHop.IA)
			if err != nil {
				return nil, err
			}
			block, err = aes.NewCipher(sv)
			if err != nil {
				return nil, serrors.Wrap("creating aes cipher", err, "ia", baseHop.IA)
			}
			aesByIA[baseHop.IA] = block
		}
		akRaw := hummlib.DeriveAuthKey(
			block,
			hummReservationID,
			hummBandwidth,
			baseHop.Ingress,
			baseHop.Egress,
			startTime,
			hummDurationSeconds,
			buffer,
		)
		var ak [hummlib.AkBufferSize]byte
		copy(ak[:], akRaw)
		flyovers = append(flyovers, &snetpath.Hop{
			BaseHop: baseHop,
			Flyover: &snetpath.FlyoverData{
				ResID:     hummReservationID,
				Ak:        ak,
				Bw:        hummBandwidth,
				StartTime: startTime,
				Duration:  hummDurationSeconds,
			},
		})
	}
	return snetpath.NewReservation(
		snetpath.WithNow(returnNow),
		snetpath.WithScionPath(path, snetpath.FlyoversToMap(flyovers)),
	)
}

func (c *client) hummSecretValue(ia addr.IA) ([]byte, error) {
	if sv, ok := c.hummSVByIA[ia]; ok {
		return sv, nil
	}
	asDir := addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator())
	keysDir := filepath.Join(c.hummKeysDir, asDir, "keys")
	master, err := keyconf.LoadMaster(keysDir)
	if err != nil {
		return nil, serrors.Wrap("loading humm master key", err, "ia", ia, "dir", keysDir)
	}
	log.Debug("Have Hummingbird master secret for IA", "ia", ia)
	sv := hummlib.DeriveSecretValue(master.Key0)
	c.hummSVByIA[ia] = sv
	return sv, nil
}

func (c *client) pong(ctx context.Context) error {
	if err := c.conn.SetReadDeadline(getDeadline(ctx)); err != nil {
		return serrors.Wrap("setting read deadline", err)
	}
	rawPld := make([]byte, common.MaxMTU)
	n, serverAddr, err := readFrom(c.conn, rawPld)
	if err != nil {
		return serrors.Wrap("reading packet", err)
	}

	var pld Pong
	if err := json.Unmarshal(rawPld[:n], &pld); err != nil {
		return serrors.Wrap("unpacking pong", err, "data", string(rawPld))
	}

	expected := Pong{
		Client:  integration.Local.IA,
		Server:  remote.IA,
		Message: pong,
	}
	if pld.Client != expected.Client || pld.Server != expected.Server || pld.Message != pong {
		return serrors.New("unexpected contents received", "data", pld, "expected", expected)
	}
	log.Info("Received pong", "server", serverAddr)
	return nil
}

func getDeadline(ctx context.Context) time.Time {
	dl, ok := ctx.Deadline()
	if !ok {
		integration.LogFatal("No deadline in context")
	}
	return dl
}

func readFrom(conn *snet.Conn, pld []byte) (int, net.Addr, error) {
	n, remoteAddr, err := conn.ReadFrom(pld)
	// Attach more context to error
	var opErr *snet.OpError
	if !errors.As(err, &opErr) || opErr.RevInfo() == nil {
		return n, remoteAddr, err
	}
	return n, remoteAddr, serrors.WrapNoStack("error", err,
		"isd_as", opErr.RevInfo().IA(),
		"interface", opErr.RevInfo().IfID)

}

type hummingbirdParameters struct {
	Bw       uint16
	Duration uint16
}
