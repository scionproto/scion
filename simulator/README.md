SCION Simulator
===============

A discrete-event simulator of SCION

Modules:

1. [lib](/lib) contains the core file of the simulator: `sim_core.py`. It runs an event queue

2. [infrastructure](/infrastructure) contains simulator versions of all infrastructure files - `RouterSim`, `CorePathServerSim`, `LocalPathServerSim`, `CoreBeaconServerSim`, `LocalBeaconServerSim` and `CertServerSim`

3. [endhost](/endhost) contains `sim_host.py` which can be used to create a host on which we can create applications to be run

4. [application](/application) contains `sim_app.py` which is a generic class for an application running on a host. It also has `sim_ping_pong.py` which inherits from the base class to run a ping pong application
