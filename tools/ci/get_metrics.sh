#!/bin/bash
## Assumes that all services are running as described in the gen and scrapes their metrics

set -e

:> metrics_locations

echo "Collecting Metrics from all scion services in gen"

# Fails if a toml (disp is the exception) in gen doesn't contain metrics->Prometheus or general->ID
for i in $(find gen/ -iname '*.toml'); do
    case $i in
       */disp.toml) id=$(sed -n '/^\[dispatcher\]/,/^$/p' "$i" | awk '/^ID = / {print $3}');; 
       *) id=$(sed -n '/^\[general\]/,/^$/p' "$i" | awk '/^ID = / {print $3}');;
    esac
    prom=$(sed -n '/^\[metrics\]/,/^$/p' "$i" | awk '/^Prometheus = / {print $3}')
    echo "${id:?} ${prom:?}" | tr -d '"[]'
done > metrics_locations

# Gather metrics from all services that are running
while read id prom_ip_port; do
    curl -sS $prom_ip_port/metrics > "/home/scion/go/src/github.com/scionproto/scion/metrics/${id}" || true
done < metrics_locations
rm metrics_locations
