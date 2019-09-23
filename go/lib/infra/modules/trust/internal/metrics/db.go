// Copyright 2019 Anapaya Systems
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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

type operation string

// Database operations.
const (
	GetIssCert     = "get_iss_cert"
	GetIssCertMax  = "get_iss_cert_max"
	GetAllIssCerts = "get_all_iss_certs"
	GetChain       = "get_chain"
	GetChainMax    = "get_chain_max"
	GetAllChains   = "get_all_chains"
	GetTRC         = "get_trc"
	GetTRCMax      = "get_trc_max"
	GetAllTRCs     = "get_all_trcs"
	GetCustKey     = "get_cust_key"
	GetAllCustKeys = "get_all_cust_keys"

	InsertIssCert = "insert_iss_cert"
	InsertChain   = "insert_chain"
	InsertTRC     = "insert_trc"
	InsertCustKey = "insert_cust_key"

	BeginTx    = "tx_begin"
	CommitTx   = "tx_commit"
	RollbackTx = "tx_rollback"
)

// QueryLabels defines the database query labels.
type QueryLabels struct {
	Driver    string
	Operation string
	Result    string
}

// Labels returns the list of labels.
func (l QueryLabels) Labels() []string {
	return []string{"driver", "operation", prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l QueryLabels) Values() []string {
	return []string{l.Driver, l.Operation, l.Result}
}

type db struct {
	queries *prometheus.CounterVec
}

func newDB() db {
	return db{
		queries: prom.NewCounterVec(Namespace, "", "db_queries_total",
			"Total queries to the database", QueryLabels{}.Labels()),
	}
}

func (d *db) Queries(l QueryLabels) prometheus.Counter {
	return d.queries.WithLabelValues(l.Values()...)
}
