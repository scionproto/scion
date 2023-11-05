.. _deployment-guide:

Deployment Tutorial
===================

This document helps you set up a SCION demo configuration, which consists of a stand-alone full-scale SCION environment distributed among five computers. The demo environment consists of one SCION Isolation Domain (ISD), with three core ASes and two non-core, leaf ASes.

- If you want to go deep and help develop SCION, use the development environment. See https://docs.scion.org/en/latest/dev/setup.html
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
- Each VM should have at least one IP address reachable by the other VMs. (If on AWS, be sure to setup the appropriate security groups.)
- Each VM will need internet access to download the required files (or you will need an alternate way to download the SCION binaries).
- One VM (scion01) should have SSH access to copy generated SCION keys to the other hosts scion{02-05}.
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


.. _step1:

OS Setup
........

The host file (*/etc/hosts*) will need to be updated with the IP addresses of 5 VMs. This will need to be updated on scion01-scion05. Replace the IP addresses with the assigned IP addresses for the VMs deployed.

.. code-block::

   10.0.1.1 scion01
   10.0.1.2 scion02
   10.0.1.3 scion03
   10.0.1.4 scion04
   10.0.1.5 scion05


.. _step2:

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With the software selected (from above), it will need to be downloaded and installed on each of the VMs scion01-scion05. 

To download the software and install it on your virtual machines, execute the following commands in your shell/terminal:

.. note::

   These steps are the same for each virtual machine. So you have to repeat these steps five times, once per virtual machine.


.. code-block::

   sudo -i

   wget https://github.com/scionproto/scion/releases/download/v0.9.1/scion_v0.9.1_amd64_linux.tar.gz

   mkdir /usr/local/scion

   tar xfz /tmp/scion_v0.9.1_amd64_linux.tar.gz -C /usr/local/scion


As each virtual machine represents an AS in your demo environment, we will now refer to the VMs as ASes.


.. _step3:

Configuration
.............

To configure your demo SCION environment, perform the following steps.

Step 2 - Download AS Specific Topology Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. For this tutorial, we have provided the AS specific topology files - one per each AS. These files have been generated from the master AS toplogy file for this tutorial deployment for simplicty. 
Now you have to create a topology file per AS. Sample topology files for each AS in our sample ISD environment are listed below. Click on the file name to download it, then copy the file to the corresponding AS.

   - **AS 1 (ffaa:1:1)**: `topology-42-ffaa:1:1.json <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/topology-42-ffaa:1:1.json>`_

   - **AS 2 (ffaa:1:2)**: `topology-42-ffaa:1:2.json <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/topology-42-ffaa:1:2.json>`_

   - **AS 3 (ffaa:1:3)**: `topology-42-ffaa:1:3.json <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/topology-42-ffaa:1:3.json>`_

   - **AS 4 (ffaa:1:4)**: `topology-42-ffaa:1:4.json <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/topology-42-ffaa:1:4.json>`_

   - **AS 5 (ffaa:1:5)**: `topology-42-ffaa:1:5.json <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/topology-42-ffaa:1:5.json>`_

  Replace IP addressed from this guide with the IPs of your machines: 

  .. code-block::

      sed -i 's/XXXX/XXXX/g' /etc/scion/topology.json


Step 2 - Generate the Required Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For this tutorial deployment, a sample topology file has been provided. As part of this tutorial deployment, this file will be processed to generated the required crypto graphics keys.

This topology file wdescribes the setup of the entire ISD environment including all 5 ASes and the associated network links between the ASes. The topology file of an AS specifies all the inter-AS connections to neighboring ASes, and defines the underlay IP/UDP addresses of services and routers running in this AS.

The topology information is needed by Router and Control Service instances, and also by end-host applications. For more information on the topology files, see `<https://docs.scion.org/en/latest/manuals/common.html#topology-json>`_

1. First, download the provided tutorial deployment topology file. This contains a concise representation of the topology drawn above. This topology file is available at: `TutorialDeploymentTopology.topo <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/TutorialDeploymentTopology.topo>`_  . Download the file to the scion01 VM.
  
.. code-block::
   
   wget https://github.com/cdekater/scion/raw/ietf118-hackathon/doc/deploy/TutorialDeploymentTopology.topo

The next step is to generate all required certificates by using the global topology file. Proceed as follows:

2. To generate all required certificates using the global topology file, execute the following command on the machine where you downloaded the global topology:

   .. code-block::

      /usr/local/scion/scion-pki testcrypto -t TutorialDeploymentTopology.topo

   This will generate all the required keys in the *gen/* directory for all the SCION ASes in all topology.

3. Now you have to copy the just-generated keys to the respective AS routers. Proceed as follows:

   - Create the required directories. 

Repeat these commands on scion01-scion05.

     .. code-block::

        mkdir -p /etc/scion/certs
        mkdir -p /etc/scion/crypto/as
        mkdir -p /etc/scion/keys




   - Copy the content of *gen/ASffaa_1_X/* to */etc/scion/* on each of the five AS routers 
     On the machine where you generated the material
   - The part *ASffaa_1_X in the last line needs to be adapted per AS, so that it contains the correct AS number for the corresponding AS.

      .. code-block::

         mkdir /etc/scion
         mkdir /etc/scion/certs
         cp -r gen/ASffaa_1_1/ /etc/scion/

      Copy from machine 1 to all other machine the respective certs

      .. code-block::

         scp -r scion1:/tmp/gen .
         scp -r  gen/ASffaa_1_X/crypto scion1:/etc/scion/
         scp -r  gen/trcs scionX:/etc/scion/certs

Step 3 - Generate  Forwarding Secret Keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two symmetric keys *master0.key* and *master1.key* are required per AS as the forwarding secret keys. These symmetric keys are used by the AS in the data plane to verify the MACs in the hop fields of a SCION path (header).

     .. code-block::

        dd if=/dev/urandom bs=16 count=1 | base64 - > /etc/scion/keys/master0.key
        dd if=/dev/urandom bs=16 count=1 | base64 - > /etc/scion/keys/master1.key

Step 4 - Create the Directories For the Support Database Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To create the required directories for the support database files, execute the following command. Do this once per each AS.

.. code-block::

   mkdir /var/lib/scion


Step 5 - Create the Configuration Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Next, you have to create ("copy over") a couple of configuration files in the */etc/scion/* directory of each AS.

The files including their names are listed below. Click on the corresponding link to download the file, then copy it into the */etc/scion/* directory of each AS.

- **Border router**: `br.toml <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/br.toml>`_

- **Control service**: `cs.toml <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/cs.toml>`_

- **Dispatcher**: `dispatcher.toml <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/dispatcher.toml>`_

- **SCION daemon**: `sd.toml <https://github.com/cdekater/scion/blob/ietf118-hackathon/doc/deploy/sd.toml>`_



Step 6 - Start the Services
~~~~~~~~~~~~~~~~~~~~~~~~~~~

As a last step, you have to start the services on each of the five ASes. Execute the following commands on every AS:

.. code-block::

   screen -dmS BR /usr/local/scion/router --config /etc/scion/br.toml
   screen -dmS BorderRouter /usr/local/scion/router --config /etc/scion/br.toml
   screen -dmS Dispatcher /usr/local/scion/dispatcher --config /etc/scion/dispatcher.toml
   screen -dmS Control /usr/local/scion/control --config /etc/scion/cs.toml
   screen -dmS Daemon /usr/local/scion/daemon --config /etc/scion/sd.toml



.. _step4:

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



