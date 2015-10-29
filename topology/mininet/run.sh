#!/bin/bash

sudo SUPERVISORD=$(which supervisord) python topology/mininet/topology.py
