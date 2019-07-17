#!/bin/bash
## Assumes that all services are running as described in the gen and scrapes their metrics

:> metrics_locations

echo "Collecting Metrics from all scion services in gen"

# Grep out ID and Prom IP/port of all toml files containing prom config.
while IFS= read -r line
do
    grep "ID =" $line | awk '{print $3}' >> metrics_locations
    grep "Prometheus =" $line | awk '{print $3}' >> metrics_locations
done < <(grep -rl 'Prometheus = ' gen)

# Gather metrics from the services found

while IFS= read -r ID
do
    read -r PROM_IP_PORT
    # Remove unneccesary chars from ID and PROM_IP_PORT
    ID=${ID//\"}
    PROM_IP_PORT=${PROM_IP_PORT//\"}
    PROM_IP_PORT=${PROM_IP_PORT//\[}
    PROM_IP_PORT=${PROM_IP_PORT//\]}
    curl -s $PROM_IP_PORT/metrics > "/home/scion/go/src/github.com/scionproto/scion/metrics/${ID}"
done < metrics_locations
rm metrics_locations
