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

// This file contains all logic to do the bandwidth enforcement within
// the router.

package enforcement

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

type BWEnforcer struct {
	// DoEnforcement indicates whether to do enforcement or not.
	DoEnforcement bool
	// Interfaces contains all interfaces that have ASes with
	// reserved bandwidth.
	Interfaces map[common.IFIDType]IFEContainer
}

// IFEContainer contains all information that is necessary to do
// bandwidth enforcement per interface.
type IFEContainer struct {
	// avgs holds all averages associated to an AS.
	avgs map[uint32]*ASEInformation
	//unknown holds the current average for unknown ASes.
	unknown ASEInformation
}

// ASEInformation contains all information necessary to do bandwidth
// enforcement for a certain AS.
type ASEInformation struct {
	// maxBw indicates the max bandwidth that the AS is allowed to use.
	maxBw int64
	// alertBW indicates the bandwidth that is used for alerting. currently it is set to 95%.
	alertBW int64
	// movAvg holds the current bandwidth average of the AS.
	movAvg *MovingAverage
	// Labels holds the prometheus labels of the AS.
	Labels prometheus.Labels
}

// Check() indicates whether a packet should be forwarded to the next stage
// of the router or not.
func (bwe *BWEnforcer) Check(rp *rpkt.RtrPkt) bool {
	ifid, _ := rp.IFCurr()
	if ifInfo, ex := bwe.Interfaces[*ifid]; ex {
		srcIA, _ := rp.SrcIA()
		length := len(rp.Raw)
		return ifInfo.canForward(srcIA, length)
	}
	return true
}

// canForward() indicates whether a packet is allowed to pass the router. It is not if
// the AS exceeds its bandwidth limit.
func (ifec *IFEContainer) canForward(isdas *addr.ISD_AS, length int) bool {
	info := ifec.getBWInfo(*isdas)
	labels := info.Labels

	//If there is unlimited BW for an AS just forward the packet.
	if info.maxBw == -1 {
		return true
	}

	//If there is no BW assigned to an AS just drop the packet.
	if info.maxBw == 0 {
		metrics.PktsDropPerAs.With(labels).Inc()
		return false
	}

	avg := info.getAvg()
	if avg < info.maxBw {
		info.addPktToAvg(length)
		if avg > info.alertBW {
			metrics.CurBwPerAs.With(labels).Set(float64(avg))
		}

		return true
	}

	metrics.CurBwPerAs.With(labels).Set(float64(avg))
	metrics.PktsDropPerAs.With(labels).Inc()
	return false
}

// getBWInfo() checks if there is a moving average for addr and returns it. If not it
// returns the moving average for unknown ASes.
func (ifec *IFEContainer) getBWInfo(addr addr.ISD_AS) ASEInformation {
	info, exists := ifec.avgs[addr.Uint32()]
	if exists {
		return *info
	}
	return ifec.unknown
}

// getAvg() returns the current moving average in bits.
func (info *ASEInformation) getAvg() int64 {
	return info.movAvg.getAverage() * 8
}

// addPktToAvg() adds the length of the packet in bytes to the moving average.
func (info *ASEInformation) addPktToAvg(length int) {
	info.movAvg.add(length)
}
