#!/bin/bash

# Small script to fully setup environment

sudo service zookeeper start
sudo mount -t tmpfs -o size=25% none /run/shm

# Can't be fixed during build due to
# https://github.com/docker/docker/issues/6828
sudo chmod g+s /usr/bin/screen

# Properly setup terminal to allow use of screen, etc:
exec bash -l >/dev/tty 2>/dev/tty </dev/tty
