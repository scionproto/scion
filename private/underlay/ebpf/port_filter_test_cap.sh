#! /bin/bash

executable=$1
shift


/usr/bin/sudo capsh --caps="cap_bpf=ep cap_net_admin=ep cap_net_raw=ep" -- -c "$executable"
