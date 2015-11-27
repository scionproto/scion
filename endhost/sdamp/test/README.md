# SCION Multipath Socket test apps

Note: This file will be updated at a later time when I update the apps
      in this directory

These applications are used to demonstrate the functionalities of the
SCION multipath socket library.

## Required libraries:
On a 64-bit machine with Ubuntu 14.04, the following libraries need to be
installed in order to build the socket library:
1. g++
2. lib64ncurses5-dev
3. libcurl4-openssl-dev

## Building
From the SCION root directory, run:
./scion.sh sock_bld

## Running
From the SCION root directory, after running the SCION infrastructure:
1. ./scion.sh sock_ser
2. ./scion.sh run_ser
3. Open new terminal window (or run step 2 in the background)
4. ./scion.sh sock_cli
5. ./scion.sh run_cli

## C wrapper for library
A C wrapper for the SCIONSocket library is defined in
[scion root dir]/endhost/sdamp/SCIONWrapper.h
Refer to wrapper_client.c and wrapper_server.c for usage.
