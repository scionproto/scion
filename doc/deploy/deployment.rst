Deployment Tutorial
===================

This document helps you set up a SCION demo configuration, which consists of a stand-alone full-scale SCION environment distributed among five computers. The demo environment contains one SCION Isolation Domain (ISD), with three core ASes and two non-core, leaf ASes.

- If you want to go deep and help develop SCION, use the development environment. See :ref:`setting-up-the-development-environment`.
- If you want to use SCION in a large environment, use the SCIONLab. For more information, see https://www.scionlab.org/

Setup
-----

This first section provides an overview of the setup and topology of the sample demo environment.

Infrastructure
..............

The sample SCION demo setup consists of one ISD with three core ASes and two non-core, leaf ASes. The following table lists some details of the sample ISD and each AS in it, such as the DNS names, the ISD- and AS numbers, the kind of AS (core or leaf) and the IP addresses. This infrastructure could be virtual machines or bare metal.

======== ==== ========= ======== =========== =============== ====================== ======== ====
Hostname ISD  AS        Purpose  Notes       IP Address      OS                     Disk     RAM
======== ==== ========= ======== =========== =============== ====================== ======== ====
scion01  42   ffaa:1:1  Core     Voting      10.0.1.1        **Ubuntu** 22.04.3 LTS 4 GB     1 GB
scion02  42   ffaa:1:2  Core     Non-Voting  10.0.1.2        **Ubuntu** 22.04.3 LTS 4 GB     1 GB
scion03  42   ffaa:1:3  Core     Non-Voting  10.0.1.3        **Ubuntu** 22.04.3 LTS 4 GB     1 GB
scion04  42   ffaa:1:4  Leaf                 10.0.1.4        **Ubuntu** 22.04.3 LTS 4 GB     1 GB
scion05  42   ffaa:1:5  Leaf                 10.0.1.5        **Ubuntu** 22.04.3 LTS 4 GB     1 GB
======== ==== ========= ======== =========== =============== ====================== ======== ====

*Table 1: Required Infrastructure*


Sample SCION Demo Topology
..........................

The topology of the ISD includes the inter-AS connections to neighboring ASes, and defines the underlay IP/UDP addresses of services and routers running in this AS. This is specified in topology files - this guide later explains how to configure these files. A following graphic depicts the topology on a high level.

.. figure:: SCION-deployment-guide.drawio.png
   :width: 95 %
   :figwidth: 100 %

   *Figure 1 - Topology of the sample SCION demo environment. It consists of 1 ISD, 3 core ASes and 2 non-core ASes.*



.. _prerequisites:

Infrastructure Prerequisites
----------------------------

This deployment requires five virtual machines (VMs) - one for each AS. We recommend using Ubuntu VMs for this.

- 5 VMs - **Ubuntu** 22.04.3 LTS (Jammy Jellyfish). For more information, see `Ubuntu Jammy Jellyfish <https://releases.ubuntu.com/jammy/>`_.
- Each VM should have at least one IP address reachable by the other VMs. (If on AWS, be sure to set up the appropriate security groups.)
- Each VM will need internet access to download the required files (or you will need an alternate way to download the SCION binaries).
- One VM (scion01) should have SSH access (password or SSH keys) to the other hosts scion{02-05} to copy generated configuration files and keys.
- Using the naming convention for each VM of scion01, scion02, scion03, scion04, and scion05 will help follow along with this tutorial.
- The VM names scion01-scion05 can be configured in /etc/hosts.


Tasks to Perform
----------------

To create the sample ISD environment, you need to perform the following tasks, in this order:

- Task 1: OS setup (:ref:`step0`)
- Task 2: Installation (:ref:`step1`)
- Task 3: Configuration (:ref:`step2`)
- Task 4: Testing your environment (:ref:`step3`)

The following sections explain the required tasks, one section per task.


.. _step0:

OS Setup
........

- Set up the host file

  The host file (*/etc/hosts*) will need to be updated with the IP addresses of 5 VMs. This will need to be updated on scion01-scion05. Replace the IP addresses with the assigned IP addresses for the VMs deployed.

  Set this up on scion01-scion05.

  .. code-block::

     # additions to /etc/hosts
     10.0.1.1 scion01
     10.0.1.2 scion02
     10.0.1.3 scion03
     10.0.1.4 scion04
     10.0.1.5 scion05


- Create required directories.

  These directories are required to store the certificates, keys, and database files.
  Repeat these commands on scion01-scion05. We assume you'll run the SCION binaries with user `ubuntu`.

  .. code-block::

     sudo mkdir /etc/scion
     sudo mkdir -p /var/lib/scion
     sudo chown -R ubuntu:ubuntu /etc/scion/
     sudo chown -R ubuntu:ubuntu /var/lib/scion/
     mkdir -p /etc/scion/certs
     mkdir -p /etc/scion/crypto/as
     mkdir -p /etc/scion/keys


.. _step1:

Software Selection, Download, and Installation
..............................................

This section guides you through the download and installation of the SCION software.

Software Selection
~~~~~~~~~~~~~~~~~~

The SCION software is available as a nightly and official release TAR file. We recommend selecting an official release.

- `Latest official release <https://github.com/scionproto/scion/releases/>`_
- `Latest nightly build <https://buildkite.com/scionproto/scion-nightly/builds/latest/>`_

In this example, we install software with the following release version: *scion_v0.9.1_amd64_linux.tar.gz*

Note that we have to install the software five times: Once per virtual machine we created previously. Proceed as described in the following sections.

Installation from packages is under development (available 2024).


Downloading and Installing the SCION Software
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With the software selected (from above), it will need to be downloaded and installed on each of the VMs scion01-scion05.

To download the software and install it on your virtual machines, execute the following commands in your shell/terminal:

.. note::

   These steps are the same for each virtual machine. So you have to repeat these steps five times, once per virtual machine.


.. code-block::

   wget https://github.com/scionproto/scion/releases/download/v0.9.1/scion_v0.9.1_amd64_linux.tar.gz

   mkdir /usr/local/scion

   tar xfz /tmp/scion_v0.9.1_amd64_linux.tar.gz -C /usr/local/scion


As each virtual machine represents an AS in your demo environment, we will now refer to the VMs as ASes.


.. _step2:

Configuration
.............

To configure your demo SCION environment, perform the following steps.

Step 1 - AS Specific Topology Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For this tutorial, we have provided the AS specific topology files - one per each AS. These files have been generated from the master AS topology file for this tutorial deployment for simplicity.
Now you have to create a topology file per AS. Sample topology files for each AS in our sample ISD environment are listed below. Click on the file name to download it, then copy the file to the corresponding AS.

   - **AS 1 (ffaa:1:1)**: :download:`topology-42-ffaa:1:1.json <topology1.json>`
   - **AS 2 (ffaa:1:2)**: :download:`topology-42-ffaa:1:2.json <topology2.json>`
   - **AS 3 (ffaa:1:3)**: :download:`topology-42-ffaa:1:3.json <topology3.json>`
   - **AS 4 (ffaa:1:4)**: :download:`topology-42-ffaa:1:4.json <topology4.json>`
   - **AS 5 (ffaa:1:5)**: :download:`topology-42-ffaa:1:5.json <topology5.json>`

Download the AS specific topology files onto each host scion01 through scion05.

Copy the download link above and use ``wget`` to download appropriate file for each host, installing it as ``/etc/scion/topology.json``.
On scion01, download the topology1.json file. On scion02, download topology2.json and repeat as such on scion03, scion04, and scion05.

.. code-block::

   wget LINK_TO_TOPOLOGY.JSON_FILE -O /etc/scion/topology.json


The downloaded AS topology file is configured with generic IP address (10.0.0.1-5) for the hosts scion01-05. These IP addresses will need to be changed to the VM IP specific addresses.

.. code-block::

   sed -i 's/10.0.0.1/YOUR_SCION01_IP/g' /etc/scion/topology.json
   sed -i 's/10.0.0.2/YOUR_SCION02_IP/g' /etc/scion/topology.json
   sed -i 's/10.0.0.3/YOUR_SCION03_IP/g' /etc/scion/topology.json
   sed -i 's/10.0.0.4/YOUR_SCION04_IP/g' /etc/scion/topology.json
   sed -i 's/10.0.0.5/YOUR_SCION05_IP/g' /etc/scion/topology.json


Repeat the above 5 times - once for each scion host replacing YOUR_SCIONXX_IP with the VM specific IP address.


Step 2 - Generate the Required Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The various cryptographic certificates need to be generated for each of the ASes. For this tutorial, we have provided the relevant AS wide topology file which will be used to generate the required keys and certificates.

This topology file describes the setup of the entire ISD environment including all 5 ASes and the associated network links between the ASes. The topology file of an AS specifies all the inter-AS connections to neighboring ASes, and defines the underlay IP/UDP addresses of services and routers running in this AS. (The AS specific topology files used above were generated from this larger AS wide topology file.)

The topology information is needed by Router and Control Service instances, and also by end-host applications. For more information on the topology files, see :ref:`common-conf-topo`.

1. First, download the provided AS wide tutorial deployment topology file. This contains a concise representation of the topology drawn above. This topology file is available at: :download:`TutorialDeploymentTopology.topo <TutorialDeploymentTopology.topo>` . Download the file to the scion01 VM.

2. Using the above AS wide tutorial file, the required certificates will be generated and then distributed across all the hosts. To generate all required certificates, execute the following command on the machine where you downloaded the global topology (scion01).

   .. code-block::

      /usr/local/scion/scion-pki testcrypto -t TutorialDeploymentTopology.topo

   This will generate all the required keys in a new *gen/* directory for all the SCION ASes.

   .. note::

      The step above will generate a new TRC for your ISD and must be done exactly once.  Once you deploy such TRC on your machines, further TRC updates must be sequential. If for any reason you need to reset your setup and you need to deploy a fresh new TRC generated with the script above, then you must first delete the local DB files on your hosts (in `/var/lib/scion/`).


3. The just-generated keys in gen/* can now be copied to the respective AS routers from scion01.

   - Copy the TRC certificates and cryptographic keys to each of the five AS routers (scion01 - scion05).

     .. code-block::

        for i in {1..5}
        do
           scp -r  gen/ASffaa_1_$i/crypto scion0$i:/etc/scion/
           scp -r  gen/trcs/ISD42-B1-S1.trc  scion0$i:/etc/scion/certs/
        done


Step 3 - Generate Forwarding Secret Keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two symmetric keys *master0.key* and *master1.key* are required per AS as the forwarding secret keys. These symmetric keys are used by the AS in the data plane to verify the MACs in the hop fields of a SCION path (header).

.. code-block::

   dd if=/dev/urandom bs=16 count=1 | base64 - > /etc/scion/keys/master0.key
   dd if=/dev/urandom bs=16 count=1 | base64 - > /etc/scion/keys/master1.key

Repeat the above on each host scion01 - scion05.


Step 4 - Service Configuration Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Next, you have to download the service configuration files into the */etc/scion/* directory of each AS host scion01-scion05.

The files including their names are listed below. Click on the corresponding link to download the file, then copy it into the */etc/scion/* directory of each AS.

- **Border router**: :download:`br.toml`
- **Control service**: :download:`cs.toml`
- **Dispatcher**: :download:`dispatcher.toml`
- **SCION daemon**: :download:`sd.toml`


Alternatively, the files can be downloaded directly onto each host with ``wget`` into the ``/etc/scion`` directory.

These steps need to be repeated on each host scion01 - scion05.

Step 5 - Start the Services
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Start the services on each of the five ASes. Execute the following commands on every AS:

.. code-block::

   /usr/local/scion/router --config /etc/scion/br.toml
   /usr/local/scion/dispatcher --config /etc/scion/dispatcher.toml
   /usr/local/scion/control --config /etc/scion/cs.toml
   /usr/local/scion/daemon --config /etc/scion/sd.toml


These steps need to be repeated on each host scion01 - scion05.


.. _step3:

Testing the Environment
.......................

You can now test your environment. The code block below includes some tests you could perform to check whether your environment works well.

Verify that each host has a SCION address. This can be verified with the "scion address" command as shown below.

.. code-block::

   scion01$ /usr/local/scion/scion address
   42-ffaa:1:1,127.0.0.1

Verify that each host can ping the other hosts via SCION. This can be done with the "scion ping" command. In the example below, we are pinging between scion01 (AS 42-ffaa:1:1) to scion05 (AS 42-ffaa:1:5). Very that each AS can ping every other AS.

.. code-block::

   scion01$ /usr/local/scion/scion ping 42-ffaa:1:5,127.0.0.1 -c 5
   Resolved local address:
   127.0.0.1
   Using path:
   Hops: [42-ffaa:1:1 3>1 42-ffaa:1:3 4>2 42-ffaa:1:5] MTU: 1472 NextHop: 127.0.0.1:31002

   PING 42-ffaa:1:5,127.0.0.1:0 pld=0B scion_pkt=112B
   120 bytes from 42-ffaa:1:5,127.0.0.1: scmp_seq=0 time=0.788ms
   120 bytes from 42-ffaa:1:5,127.0.0.1: scmp_seq=1 time=3.502ms
   120 bytes from 42-ffaa:1:5,127.0.0.1: scmp_seq=2 time=3.313ms
   120 bytes from 42-ffaa:1:5,127.0.0.1: scmp_seq=3 time=3.838ms
   120 bytes from 42-ffaa:1:5,127.0.0.1: scmp_seq=4 time=3.401ms

   --- 42-ffaa:1:5,127.0.0.1 statistics ---
   5 packets transmitted, 5 received, 0% packet loss, time 5000.718ms
   rtt min/avg/max/mdev = 0.788/2.968/3.838/1.105 ms

Verify that each host has a full table of available paths to the other ASes. This can be done with the "scion showpaths" command. In the example below, we are displaying the paths between scion01 (AS 42-ffaa:1:1) to scion05 (AS 42-ffaa:1:5). There should be multiple paths through the core ASes.

.. code-block::

   scion01$ /usr/local/scion/scion showpaths 42-ffaa:1:5
   Available paths to 42-ffaa:1:5
   3 Hops:
   [0] Hops: [42-ffaa:1:1 2>1 42-ffaa:1:2 3>1 42-ffaa:1:5] MTU: 1472 NextHop: 127.0.0.1:31002 Status: alive LocalIP: 127.0.0.1
   [1] Hops: [42-ffaa:1:1 3>1 42-ffaa:1:3 4>2 42-ffaa:1:5] MTU: 1472 NextHop: 127.0.0.1:31002 Status: alive LocalIP: 127.0.0.1
   4 Hops:
   [2] Hops: [42-ffaa:1:1 2>1 42-ffaa:1:2 2>2 42-ffaa:1:3 4>2 42-ffaa:1:5] MTU: 1472 NextHop: 127.0.0.1:31002 Status: alive LocalIP: 127.0.0.1
   [3] Hops: [42-ffaa:1:1 3>1 42-ffaa:1:3 2>2 42-ffaa:1:2 3>1 42-ffaa:1:5] MTU: 1472 NextHop: 127.0.0.1:31002 Status: alive LocalIP: 127.0.0.1



