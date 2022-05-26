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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/tools/pktgen"
)

type flags struct {
	daemon      string
	out         string
	logLevel    string
	payload     int
	config      string
	sequence    string
	interactive bool
	noColor     bool
	refresh     bool
}

func main() {
	cfg := flags{}
	executable := filepath.Base(os.Args[0])
	cmd := &cobra.Command{
		Use:   executable,
		Short: "SCION packet creator",
		Args:  cobra.ExactArgs(1),
		Example: "  " + executable +
			" -p 40 -c config.json -o pkt.pcap 1-ff00:0:110,10.0.0.1:404",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			dst, err := snet.ParseUDPAddr(args[0])
			if err != nil {
				return serrors.WrapStr("parsing destination addr", err)
			}
			return run(cfg, dst)
		},
	}
	cmd.AddCommand(
		command.NewSample(cmd,
			newSampleConfig,
		),
		command.NewVersion(cmd),
	)
	cmd.Flags().StringVar(&cfg.daemon, "daemon", daemon.DefaultAPIAddress,
		"The SCION daemon address.")
	cmd.Flags().StringVar(&cfg.sequence, "sequence", "", app.SequenceUsage)
	cmd.Flags().BoolVarP(&cfg.interactive, "interactive", "i", false, "interactive mode")
	cmd.Flags().BoolVar(&cfg.noColor, "no-color", false, "disable colored output")
	cmd.Flags().BoolVar(&cfg.refresh, "refresh", false, "set refresh flag for path request")
	cmd.Flags().IntVarP(&cfg.payload, "payload", "p", 32, "The payload size in bytes.")
	cmd.Flags().StringVarP(&cfg.config, "config", "c", "pktgen.json",
		"The configuration for the lower layers.")
	cmd.Flags().StringVarP(&cfg.out, "out", "o", "pktgen.pcap", "The name of the output file.")
	cmd.Flags().StringVar(&cfg.logLevel, "log.level", "info", "The level of the log.")
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run(cfg flags, dst *snet.UDPAddr) error {
	defer log.Flush()
	log.Setup(log.Config{Console: log.ConsoleConfig{Level: cfg.logLevel}})

	raw, err := os.ReadFile(cfg.config)
	if err != nil {
		return serrors.WrapStr("reading config file", err)
	}
	var layersCfg jsonConfig
	if err := json.Unmarshal(raw, &layersCfg); err != nil {
		return serrors.WrapStr("parsing layers config", err, "file", cfg.config)
	}
	ethernetLayer, err := parseEthernet(&layersCfg)
	if err != nil {
		return serrors.WrapStr("parsing ethernet config", err, "file", cfg.config)
	}
	ipv4Layer := parseIPv4(&layersCfg)
	udpLayer := parseUDP(&layersCfg)
	udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	scionLayer := parseSCION(&layersCfg)

	ctx := app.WithSignal(context.Background(), os.Kill)
	sdConn, err := daemon.NewService(cfg.daemon).Connect(ctx)
	if err != nil {
		return serrors.WrapStr("connecting to SCION daemon", err)
	}
	defer sdConn.Close()
	localIA, err := sdConn.LocalIA(ctx)
	if err != nil {
		return serrors.WrapStr("determining local ISD-AS", err)
	}
	path, err := path.Choose(ctx, sdConn, dst.IA,
		path.WithInteractive(cfg.interactive),
		path.WithRefresh(cfg.refresh),
		path.WithSequence(cfg.sequence),
		path.WithColorScheme(path.DefaultColorScheme(cfg.noColor)),
	)
	if err != nil {
		return serrors.WrapStr("fetching paths", err)
	}
	dst.NextHop = path.UnderlayNextHop()
	dst.Path = path.Dataplane()
	localIP, err := resolveLocal(dst)
	if err != nil {
		return serrors.WrapStr("resolving local IP", err)
	}
	scionPath, ok := path.Dataplane().(snetpath.SCION)
	if !ok {
		return serrors.New("not a scion path", "type", common.TypeOf(path))
	}
	decPath := &scion.Decoded{}
	if err := decPath.DecodeFromBytes(scionPath.Raw); err != nil {
		return serrors.WrapStr("decoding path", err)
	}

	scionLayer.PathType = scion.PathType
	scionLayer.SrcIA = localIA
	scionLayer.DstIA = path.Destination()
	scionLayer.Path = decPath
	if err := scionLayer.SetDstAddr(&net.IPAddr{IP: dst.Host.IP, Zone: dst.Host.Zone}); err != nil {
		return serrors.WrapStr("setting SCION dest address", err)
	}
	if err := scionLayer.SetSrcAddr(&net.IPAddr{IP: localIP}); err != nil {
		return serrors.WrapStr("setting SCION source address", err)
	}
	scionudpLayer := &slayers.UDP{}
	scionudpLayer.SrcPort = 40111
	scionudpLayer.DstPort = 40222
	scionudpLayer.SetNetworkLayerForChecksum(scionLayer)
	payload := make([]byte, cfg.payload)

	input := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(input, options, ethernetLayer, ipv4Layer, udpLayer,
		scionLayer, scionudpLayer, gopacket.Payload(payload)); err != nil {
		return serrors.WrapStr("serializing go packet", err)
	}
	if err := pktgen.StorePcap(cfg.out, input.Bytes()); err != nil {
		return err
	}
	fmt.Printf("Successfully written to: %[1]s\nTo staturate a link do:\n"+
		"tcpreplay -i eth7 -tK --loop 5000 --unique-ip %[1]s\n", cfg.out)
	return nil
}

func resolveLocal(dst *snet.UDPAddr) (net.IP, error) {
	target := dst.Host.IP
	if dst.NextHop != nil {
		target = dst.NextHop.IP
	}
	localIP, err := addrutil.ResolveLocal(target)
	if err != nil {
		return nil, serrors.WrapStr("resolving local address", err)

	}
	return localIP, nil
}

func newSampleConfig(pather command.Pather) *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "config",
		Short:   "Display sample config file",
		Example: fmt.Sprintf("  %[1]s config > config.json", pather.CommandPath()),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(sample)
			return nil
		},
	}
	return cmd
}

var sample string = `{
    "ethernet": {
        "SrcMAC": "f0:0d:ca:fe:be:ef",
        "DstMAC": "f0:0d:ca:fe:00:13",
        "EthernetType": 2048
    },
    "ipv4": {
        "SrcIP": "10.0.0.40",
        "DstIP": "10.0.0.45"
    },
    "udp": {
        "SrcPort": 4000,
        "DstPort": 5000
    },
    "scion": {
        "TrafficClass": 184,
        "FlowID": 2002
    }
}
`
