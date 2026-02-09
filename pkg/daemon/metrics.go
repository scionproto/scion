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

package daemon

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/daemon/private/standalone"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/private/storage/cleaner"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

const cleanerMetricSubsystem = "cleaner"

type StandaloneMetrics struct {
	Trust               trustmetrics.Metrics
	Cleaner             CleanerMetrics
	Standalone          standalone.Metrics
	TrustStorageQueries func(driver, operation, result string) metrics.Counter
}

func NewStandaloneMetrics(opts ...metrics.Option) StandaloneMetrics {
	auto := metrics.ApplyOptions(opts...).Auto()
	truststorageQueries := auto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trustengine_db_queries_total",
			Help: "Total queries to the database",
		},
		[]string{"driver", "operation", "result"},
	)

	return StandaloneMetrics{
		Trust:      trustmetrics.New(opts...),
		Cleaner:    NewCleanerMetrics(opts...),
		Standalone: standalone.NewMetrics(opts...),
		TrustStorageQueries: func(driver, operation, result string) metrics.Counter {
			return truststorageQueries.With(prometheus.Labels{
				"driver":    driver,
				"operation": operation,
				"result":    result,
			})
		},
	}
}

type CleanerMetrics struct {
	PathStorage  cleaner.Metrics
	SDSegments   cleaner.Metrics
	SDRevocation cleaner.Metrics
}

// NewCleanerMetrics creates a fully populates CleanerMetrics struct based on
// the registry specified in the options.
func NewCleanerMetrics(opts ...metrics.Option) CleanerMetrics {
	auto := metrics.ApplyOptions(opts...).Auto()
	return CleanerMetrics{
		PathStorage:  newCleanerMetric(auto, "control_pathstorage"),
		SDSegments:   newCleanerMetric(auto, "sd_segments"),
		SDRevocation: newCleanerMetric(auto, "sd_revocation"),
	}
}

func newCleanerMetric(auto metrics.Factory, namespace string) cleaner.Metrics {
	results := auto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: cleanerMetricSubsystem,
			Name:      "results_total",
			Help:      "Results of running the cleaner, either ok or err",
		},
		[]string{"result"},
	)
	deleted := auto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: cleanerMetricSubsystem,
			Name:      "deleted_total",
			Help:      "Number of deleted entries total.",
		},
	)

	return cleaner.Metrics{
		ErrorsTotal:  results.With(prometheus.Labels{"result": "err"}),
		RunsTotal:    results.With(prometheus.Labels{"result": "ok"}),
		DeletedTotal: deleted,
	}
}
