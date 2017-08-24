// Copyright 2016 ETH Zurich
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

// This file contains the main router processing loop.

package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rcmn"
	"github.com/netsec-ethz/scion/go/border/rctx"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
)

var sighup chan os.Signal

func init() {
	// Add a SIGHUP handler as soon as possible on startup, to reduce the
	// chance that a premature SIGHUP will kill the process. This channel is
	// used by confSig below.
	sighup = make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
}

type Router struct {
	// Id is the SCION element ID, e.g. "br4-21-9".
	Id string
	// confDir is the directory containing the configuration file.
	confDir string
	// freePkts is a ring-buffer of unused packets.
	freePkts *ringbuf.Ring
	// revInfoQ is a channel for handling RevInfo payloads.
	revInfoQ chan rpkt.RevTokenCallbackArgs
}

func NewRouter(id, confDir string) (*Router, *common.Error) {
	metrics.Init(id)
	r := &Router{Id: id, confDir: confDir}
	if err := r.setup(); err != nil {
		return nil, err
	}
	return r, nil
}

// Run sets up networking, and starts go routines for handling the main packet
// processing as well as various other router functions.
func (r *Router) Run() *common.Error {
	go r.SyncInterface()
	go r.IFStateUpdate()
	go r.RevInfoFwd()
	go r.confSig()
	// TODO(shitz): Here should be some code to periodically check the discovery
	// service for updated info.
	var wait chan struct{}
	<-wait
	return nil
}

// confSig handles reloading the configuration when SIGHUP is received.
func (r *Router) confSig() {
	defer liblog.LogPanicAndExit()
	for range sighup {
		var err *common.Error
		var config *conf.Conf
		if config, err = r.loadNewConfig(); err != nil {
			log.Error("Error reloading config", err.Ctx...)
			continue
		}
		if err = r.setupNewContext(config); err != nil {
			log.Error("Error setting up new context", err.Ctx...)
			continue
		}
		log.Info("Config reloaded")
	}
}

func (r *Router) handleSock(s *rctx.Sock, stop, stopped chan struct{}) {
	defer liblog.LogPanicAndExit()
	defer close(stopped)
	pkts := make(ringbuf.EntryList, 32)
	log.Debug("handleSock starting", "sock", *s)
	for {
		n, _ := s.Ring.Read(pkts, true)
		if n < 0 {
			log.Debug("handleSock stopping", "sock", *s)
			return
		}
		for i := 0; i < n; i++ {
			rp := pkts[i].(*rpkt.RtrPkt)
			r.processPacket(rp)
			rp.Release()
			pkts[i] = nil
		}
	}
}

// processPacket is the heart of the router's packet handling. It delegates
// everything from parsing the incoming packet, to routing the outgoing packet.
func (r *Router) processPacket(rp *rpkt.RtrPkt) {
	if assert.On {
		assert.Must(len(rp.Raw) > 0, "Raw must not be empty")
		assert.Must(rp.DirFrom != rcmn.DirUnset, "DirFrom must be set")
		assert.Must(rp.TimeIn != 0, "TimeIn must be set")
		assert.Must(rp.Ingress.Dst != nil, "Ingress.Dst must be set")
		assert.Must(rp.Ingress.Src != nil, "Ingress.Src must be set")
		assert.Must(len(rp.Ingress.IfIDs) > 0, "Ingress.IfIDs must not be empty")
		assert.Must(rp.Ctx != nil, "Context must be set")
	}
	// Assign a pseudorandom ID to the packet, for correlating log entries.
	rp.Id = logext.RandId(4)
	rp.Logger = log.New("rpkt", rp.Id)
	// XXX(kormat): uncomment for debugging:
	//rp.Debug("processPacket", "raw", rp.Raw)
	if err := rp.Parse(); err != nil {
		r.handlePktError(rp, err, "Error parsing packet")
		return
	}
	// Validation looks for errors in the packet that didn't break basic
	// parsing.
	if err := rp.Validate(); err != nil {
		r.handlePktError(rp, err, "Error validating packet")
		return
	}
	// Check if the packet needs to be processed locally, and if so register
	// hooks for doing so.
	if err := rp.NeedsLocalProcessing(); err != nil {
		rp.Error("Error checking for local processing", err.Ctx...)
		return
	}
	// Parse the packet payload, if a previous step has registered a relevant
	// hook for doing so.
	if _, err := rp.Payload(true); err != nil {
		// Any errors at this point are application-level, and hence not
		// calling handlePktError, as no SCMP errors will be sent.
		rp.Error("Error parsing payload", err.Ctx...)
		return
	}
	// Process the packet, if a previous step has registered a relevant hook
	// for doing so.
	if err := rp.Process(); err != nil {
		r.handlePktError(rp, err, "Error processing packet")
		return
	}
	// If the packet's destination is this router, there's no need to forward
	// it.
	if rp.DirTo != rcmn.DirSelf {
		if err := rp.Route(); err != nil {
			r.handlePktError(rp, err, "Error routing packet")
		}
	}
}
