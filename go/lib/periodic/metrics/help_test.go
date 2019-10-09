package metrics

// This files exists until we resolve https://github.com/scionproto/scion/issues/3238
// The following code was taken from prometheus/testutil/testutil.go
// as was at commit b3d60964321a277b1ab2c18d912f204acc30a7c3
import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

func collectAndCompare(c prometheus.Collector, expected io.Reader, metricNames ...string) error {
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		return fmt.Errorf("registering collector failed: %s", err)
	}
	return gatherAndCompare(reg, expected, metricNames...)
}

// GatherAndCompare gathers all metrics from the provided Gatherer and compares
// it to an expected output read from the provided Reader in the Prometheus text
// exposition format. If any metricNames are provided, only metrics with those
// names are compared.
func gatherAndCompare(g prometheus.Gatherer, expected io.Reader, metricNames ...string) error {
	got, err := g.Gather()
	if err != nil {
		return fmt.Errorf("gathering metrics failed: %s", err)
	}
	if metricNames != nil {
		got = filterMetrics(got, metricNames)
	}
	var tp expfmt.TextParser
	wantRaw, err := tp.TextToMetricFamilies(expected)
	if err != nil {
		return fmt.Errorf("parsing expected metrics failed: %s", err)
	}
	want := normalizeMetricFamilies(wantRaw)

	return compare(got, want)
}

// compare encodes both provided slices of metric families into the text format,
// compares their string message, and returns an error if they do not match.
// The error contains the encoded text of both the desired and the actual
// result.
func compare(got, want []*dto.MetricFamily) error {
	var gotBuf, wantBuf bytes.Buffer
	enc := expfmt.NewEncoder(&gotBuf, expfmt.FmtText)
	for _, mf := range got {
		if err := enc.Encode(mf); err != nil {
			return fmt.Errorf("encoding gathered metrics failed: %s", err)
		}
	}
	enc = expfmt.NewEncoder(&wantBuf, expfmt.FmtText)
	for _, mf := range want {
		if err := enc.Encode(mf); err != nil {
			return fmt.Errorf("encoding expected metrics failed: %s", err)
		}
	}

	if wantBuf.String() != gotBuf.String() {
		return fmt.Errorf(`
metric output does not match expectation; want:
%s
got:
%s`, wantBuf.String(), gotBuf.String())

	}
	return nil
}

func filterMetrics(metrics []*dto.MetricFamily, names []string) []*dto.MetricFamily {
	var filtered []*dto.MetricFamily
	for _, m := range metrics {
		for _, name := range names {
			if m.GetName() == name {
				filtered = append(filtered, m)
				break
			}
		}
	}
	return filtered
}

type metricSorter []*dto.Metric

func (s metricSorter) Len() int {
	return len(s)
}

func (s metricSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s metricSorter) Less(i, j int) bool {
	if len(s[i].Label) != len(s[j].Label) {
		// This should not happen. The metrics are
		// inconsistent. However, we have to deal with the fact, as
		// people might use custom collectors or metric family injection
		// to create inconsistent metrics. So let's simply compare the
		// number of labels in this case. That will still yield
		// reproducible sorting.
		return len(s[i].Label) < len(s[j].Label)
	}
	for n, lp := range s[i].Label {
		vi := lp.GetValue()
		vj := s[j].Label[n].GetValue()
		if vi != vj {
			return vi < vj
		}
	}

	// We should never arrive here. Multiple metrics with the same
	// label set in the same scrape will lead to undefined ingestion
	// behavior. However, as above, we have to provide stable sorting
	// here, even for inconsistent metrics. So sort equal metrics
	// by their timestamp, with missing timestamps (implying "now")
	// coming last.
	if s[i].TimestampMs == nil {
		return false
	}
	if s[j].TimestampMs == nil {
		return true
	}
	return s[i].GetTimestampMs() < s[j].GetTimestampMs()
}

// NormalizeMetricFamilies returns a MetricFamily slice with empty
// MetricFamilies pruned and the remaining MetricFamilies sorted by name within
// the slice, with the contained Metrics sorted within each MetricFamily.
func normalizeMetricFamilies(
	metricFamiliesByName map[string]*dto.MetricFamily) []*dto.MetricFamily {
	for _, mf := range metricFamiliesByName {
		sort.Sort(metricSorter(mf.Metric))
	}
	names := make([]string, 0, len(metricFamiliesByName))
	for name, mf := range metricFamiliesByName {
		if len(mf.Metric) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	result := make([]*dto.MetricFamily, 0, len(names))
	for _, name := range names {
		result = append(result, metricFamiliesByName[name])
	}
	return result
}
