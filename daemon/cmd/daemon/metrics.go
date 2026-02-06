// Copyright 2026 Anapaya Systems
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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/private/drkey"
	"github.com/scionproto/scion/private/storage/cleaner"
)

const cleanerMetricSubsystem = "cleaner"

type cleanerMetrics struct {
	PathStorage  cleaner.Metrics
	SDSegments   cleaner.Metrics
	SDRevocation cleaner.Metrics
	DRKeyClient  drkey.ClientCleanerMetrics
}

func newCleanerMetrics() cleanerMetrics {
	return cleanerMetrics{
		PathStorage:  newCleanerMetric("control_pathstorage_cleaner"),
		SDSegments:   newCleanerMetric("sd_segments"),
		SDRevocation: newCleanerMetric("sd_revocation"),
		DRKeyClient: drkey.ClientCleanerMetrics{
			ASHost:   newCleanerMetric("drkey_client_as_host_store"),
			HostAS:   newCleanerMetric("drkey_client_host_as_store"),
			HostHost: newCleanerMetric("drkey_client_host_host_store"),
		},
	}
}

func newCleanerMetric(namespace string) cleaner.Metrics {
	requests := prom.NewCounterVec(
		namespace,
		cleanerMetricSubsystem,
		"results_total",
		"Results of running the cleaner, either ok or err",
		[]string{"result"},
	)
	return cleaner.Metrics{
		ErrorsTotal: requests.With(prometheus.Labels{"result": "err"}),
		RunsTotal:   requests.With(prometheus.Labels{"result": "ok"}),
		DeletedTotal: prom.NewCounter(
			namespace,
			cleanerMetricSubsystem,
			"deleted_total",
			"Number of deleted entries total.",
		),
	}
}
