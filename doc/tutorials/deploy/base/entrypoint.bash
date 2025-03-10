#!/bin/bash

set -e
echo "Starting SCION services..."
systemctl start scion-router@br.service
systemctl start scion-control@cs.service
systemctl start scion-daemon.service

# Keep the container running
echo "SCION services are running."
exec tail -f /dev/null
