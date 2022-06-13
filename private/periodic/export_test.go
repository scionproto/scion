package periodic

func (r *Runner) GetMetric() Metrics {
	return *r.metric
}
