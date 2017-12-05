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
	// maxIfBw indicates the maximum bandwidth for the interface
	// either ingress or egress
	maxIfBw int64
	//unknown holds the current average for unknown ASes.
	unknown ASEInformation
	// ifMovAvg holds the current avg used by all reserved BW ASes.
	ifMovAvg *MovingAverage
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
	asInfo, exists := ifec.getBWInfo(*isdas)
	labels := asInfo.Labels

	if exists {
		if asInfo.maxBw == 0 {
			metrics.PktsDropPerAs.With(labels).Inc()
			return false
		}
		curAsBw := asInfo.getAvg()
		if curAsBw < asInfo.maxBw {
			asInfo.addPktToAvg(length)
			ifec.ifMovAvg.add(length)
			if curAsBw > asInfo.alertBW {
				metrics.CurBwPerAs.With(labels).Set(float64(curAsBw))
			}
			return true
		}

		metrics.CurBwPerAs.With(labels).Set(float64(curAsBw))
	} else {
		curAsBw := asInfo.getAvg()
		curIfBw := ifec.ifMovAvg.getAverage() * 8
		freeIfBw := ifec.maxIfBw - curIfBw
		// 0.75 * maxIFBw && (curAsBw < maxAsBw || curAsBw < freeIfBw )
		if (curAsBw < (ifec.maxIfBw>>1 + ifec.maxIfBw>>2)) && (curAsBw < asInfo.maxBw || curAsBw < freeIfBw) {
			asInfo.addPktToAvg(length)
			return true
		}
	}

	metrics.PktsDropPerAs.With(labels).Inc()
	return false
}

// getBWInfo() checks if there is a moving average for addr and returns it. If not it
// returns the moving average for unknown ASes.
func (ifec *IFEContainer) getBWInfo(addr addr.ISD_AS) (ASEInformation, bool) {
	info, exists := ifec.avgs[addr.Uint32()]
	if exists {
		return *info, true
	}
	return ifec.unknown, false
}

func (info *ASEInformation) getAvg() int64 {
	return info.movAvg.getAverage() * 8
}

// addPktToAvg() adds the packet to the moving average
func (info *ASEInformation) addPktToAvg(length int) {
	info.movAvg.add(length)
}
