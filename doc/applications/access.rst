Access and Host Configuration
=============================

To use any of the SCION applications, you must have access to a SCION network and have a SCION endhost stack installed on your host.
We assume that the SCION daemon runs on the default address. Otherwise, you must specify the address of the SCION daemon to which you want to attach the application, using the `SCION_DAEMON_ADDRESS` environment variable, e.g.:

.. code-block:: console

  export SCION_DAEMON_ADDRESS=127.0.0.1:30255

SCION production network
------------------------
The SCION production network is a global real-wordl network that provides secure and reliable communication.

In order to access the SCION production network, your network provider must have enabled SCION connectivity for your host, e.g.:
- You are a customer of an ISP that provides SCION connectivity.
- Your university or reasearch institution provides SCION connectivity as part of the SCIERA ISD (see `https://sciera.readthedocs.io/en/latest/index.html`).

**Preferred Host configuration**

The easiest way to install and configure the SCION endhost stack is to use the `SCION endhost installer<https://sciera.readthedocs.io/en/latest/services/scion-host.html>`_.

**Alternative Linux host configuration**

If your network provider does not provide a SCION bootstrapper service, you can manually install the debian packages (see `SCION Installation<https://docs.scion.org/en/latest/manuals/install.html#installation>`).
Additionally, you will require a valid configuration from your network provider consisting of `/etc/scion/topology.json` and `/etc/scion/hosts)`.

**Alternative macOS host configuration**

Homebrew support will be added in the future. 
For now, you can build the SCION endhost stack from source (see `SCION Build<https://docs.scion.org/en/latest/dev/build.html#build>`).
Depending where you compile the binaries, you may need to specify and `GOOS=darwin` and `GOARCH=amd64` (or your target architecture).

**Alternative Windows host configuration**

You can build the SCION endhost stack from source (see `SCION Build<https://docs.scion.org/en/latest/dev/build.html#build>`).
Depending where you compile the binaries, you may need to specify and `GOOS=windows` and `GOARCH=amd64` (or your target architecture).

SCIONLab network
----------------
The SCIONLab network is a global testbed (not production) that runs as SCION as an overlay network protocol. 
It is used for experimental purposes, altough one can deploy real applications on it. 
It is free to use and open to everyone, but one cannot expect the same level of reliability, performance and security as the SCION production network.

In order to access the SCIONLab network, you must have a SCIONLab account and have set up a SCIONLab node (see `https://docs.scionlab.org/`).
The SCIONLab node already comes with a SCION endhost stack, meaning that you can run SCION applications directly on the node.
Otherwise, you can use the SCION endhost installer to install the SCION endhost stack on your host and connect to the SCIONLab node. You can follow the instructions in `SCION production network` adapting the configuration accordingly.


Local SCION network for development
-----------------------------------
To set up a local SCION network for development, you must have a development environment set up (see `https://docs.scion.org/en/latest/dev/setup.html`).
If you have a running development environment, you can run the SCION applications on your host.
You need to specify the address of the SCION daemon to which you want to attach the application, using the `SCION_DAEMON_ADDRESS` environment variable.
The different sciond addresses can be found in their corresponding sd.toml configuration files in the gen/ASx directory.

