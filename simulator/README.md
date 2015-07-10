SCION Simulator
===============

A discrete-event simulator of SCION

Modules:

1. [lib](/simulator/lib) contains the core file of the simulator: `sim_core.py`. It runs an event queue. It also contains the `Simulator` class which is finally run

2. [infrastructure](/simulator/infrastructure) contains simulator versions of all infrastructure files - `RouterSim`, `CorePathServerSim`, `LocalPathServerSim`, `CoreBeaconServerSim`, `LocalBeaconServerSim` and `CertServerSim`

3. [endhost](/simulator/endhost) contains `sim_host.py` which can be used to create a host on which we can create applications to be run

4. [application](/simulator/application) contains `sim_app.py` which is a generic class for an application running on a host. It also has `sim_ping_pong.py` which inherits from the base class to run a ping pong application

5. `simulator.py` contains `init_simulator` which initializes a `Simulator` instance and generates the infrastructure in simulator mode from conf file


General Steps in using the simulator
====================================

1. Generate the conf files necessary to run a simulation by executing the command `./scion.sh topology --sim`

2. Use the `init_simulator` function in `simulator.py` to start the simulator. It also returns the simulator instance

3. For adding events to the simulator's event queue, use the `Simulator.add_event` function

4. Create Simulator Hosts using `SCIONSimHost` class. Applications can be run on a host using `SCIONSimApplication` class

5. Run the simulator using `Simulator.run`, and terminate it using `Simulator.terminate`


An example usage of simulator can be found at `test/integration/pingpong_sim_test.py`. One can run this directly after step 1.
