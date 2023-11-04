.. _deployment-guide:

Setting Up a Demo Environment
=============================

This document helps you set up a SCION demo environment, which consists of a stand-alone full-scale SCION environment distributed among five computers. The demo environment resembles one SCION Isolation Domain, with three core ASes and three non-core, leaf ASes.


Setup
-----


Sample SCION Setup
..................

This is the sample setup:

======================= ==== ========= ======== =================
DNS Name                ISD  AS        Purpose  Notes
======================= ==== ========= ======== =================
scion01.martincoit.net  42   ffaa:1:1  Core     ISD Voting
scion02.martincoit.net  42   ffaa:1:2  Core     ISD Voting
scion04.martincoit.net  42   ffaa:1:3  Core     ISD Voting
scion05.martincoit.net  42   ffaa:1:4  Leaf
scion06.martincoit.net  42   ffaa:1:5  Leaf
======================= ==== ========= ======== =================

*Table 1: Sample setup*


Sample SCION Topology
.....................

The SCION topology looks like this:

.. figure:: SCION-deployment-guide.drawio.png
   :width: 95 %
   :figwidth: 100 %

   *Topology of the sample SCION demo environment*



.. _prerequisites:

Prerequisites
-------------

There are some prerequisites before you can start setting up your demo environment. These are listed here:


- 5 VMs - **Ubuntu** 22.04.3 LTS (Jammy Jellyfish). For more information, see `Ubuntu Jammy Jellyfish <https://releases.ubuntu.com/jammy/>`_. These 5 virtual maschines resemble the ASes shown in the setup overview above - each maschine is one AS.

.. note::

   It is useful to give the machines names that fit/suit the setup of your demo environment.



Tasks to Perform
----------------

To create this environment, you need to perform the following tasks, in this order:

- Task 1: Installation (:ref:`step1`)
- Task 2: Configuration (:ref:`step2`)
- Task 3: Making sure the environment works (:ref:`step3`)
- Task 4: Testing (:ref:`step4`)

The following sections explain the required tasks, one section per task.


.. _step1:

Installation
............

This section guides you through the installation of the SCION software.
Here is where you can get the software:

- Install from packages (coming later in 2024).
- Install from binaries. The latest software can be found at:

  - `Latest official release <https://github.com/scionproto/scion/releases/>`_
  - `Latest nightly build <https://buildkite.com/scionproto/scion-nightly/builds/latest/>`_


In this example, we install software with the following release version:
*scion_v0.9.1_amd64_linux.tar.gz*

Note that we have to install the software five times: Once for each virual machine we created previously, where three machines represent core ASes and two machines are non-core, leaf ASes. Proceed as described in the following sections.


Downloading and Installing the SCION Software
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To download the software and install it on your virtual machines, execute the following commands in your shell/terminal:

.. note::

   These steps are the same for each virtual machine. So you have to repeat these steps five times, once per virtual machine.


.. code-block::

   Sudo -i

   Cd /tmp

   wget https://github.com/scionproto/scion/releases/download/v0.9.1/scion_v0.9.1_amd64_linux.tar.gz

   Mkdir /usr/local/scion

   Cd /usr/local/scion

   tar xfz /tmp/scion_v0.9.1_amd64_linux.tar.gz


As each virtual machine represents an AS in your demo environment, we will now refer to the VMs as ASes.


.. _step2:

Configuration
.............

To configure your demo SCION environment, perform the following steps.


Step 1 - Configure the topology (files)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First, you have to configure the topology files for your demo environment.
You have to create is one "global" topology file which describes the setup of the entire ISD environment, as well as one specific AS  topology file, one for each of the ASes in your demo ISD. The topology file of an AS specifies all the inter-AS connections to neighboring ASes, and defines the underlay IP/UDP addresses of services and routers running in this AS. This implies that the topology file will be different for each AS in your demo environment.

The topology information is needed by Router and Control Service instances, and also by end-host applications. For more information on the topology files, see `<https://docs.scion.org/en/latest/manuals/common.html#topology-json>`_

1. First, create a "global" topology file with the name *GlobalDeploymentTopology.topo*, by executing the following command:

   .. code-block::

      Cat > GlobalDeploymentTopology.topo

2. Fill this file with the following content:

   .. code-block::

      ASes:
        "42-ffaa:1:1":
          core: true
          voting: true
          authoritative: true
          issuing: true
        "42-ffaa:1:2":
          core: true
          cert_issuer: 42-ffaa:1:1
        "42-ffaa:1:3":
          core: true
          cert_issuer: 42-ffaa:1:1
        "42-ffaa:1:4":
          cert_issuer: 42-ffaa:1:1
        "42-ffaa:1:5":
          cert_issuer: 42-ffaa:1:1

      links:
        - {a: "42-ffaa:1:1#1", b: "42-ffaa:1:4#1", linkAtoB: CHILD}
        - {a: "42-ffaa:1:1#2", b: "42-ffaa:1:2#1", linkAtoB: CORE}
        - {a: "42-ffaa:1:1#3", b: "42-ffaa:1:3#1", linkAtoB: CORE}
        - {a: "42-ffaa:1:2#2", b: "42-ffaa:1:3#2", linkAtoB: CORE}
        - {a: "42-ffaa:1:2#3", b: "42-ffaa:1:5#1", linkAtoB: CHILD}
        - {a: "42-ffaa:1:3#3", b: "42-ffaa:1:4#2", linkAtoB: CHILD}
        - {a: "42-ffaa:1:3#4", b: "42-ffaa:1:5#2", linkAtoB: CHILD}


3. Save the just-created global topology file (with the name *GlobalDeploymentTopology.topo*).

4. Now you have to create a topology file per AS. **TODO**


Step 2 - Generate all required certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The next step is to generate all required certificates by using the global topology file. Proceed as follows:

1. To generate all required certificates using the global topology file, execute the following command:

   .. code-block::

      /usr/local/scion/scion-pki testcrypto -t GlobalDeploymentTopology.topo

   This will generate all the required keys in the *gen/* directory.

2. Now you have to distribute the just-generated keys to the AS routers. Proceed as follows:

   - Copy the *gen/* directory with its content to each of the five AS routers. **TODO**
   - Now for each AS, execute the commands in the following code block. Pay attention to the following:

     - All lines except for the last line are the same for each AS.
     - The part *ASffaa_1_1* in the last line needs to be adapted per AS, so that it contains the correct AS number for the corresponding AS.

     .. code-block::

        mkdir -p /etc/scion/keys
        dd if=/dev/urandom bs=16 count=1 | base64 - > /etc/scion/keys/master0.key
        dd if=/dev/urandom bs=16 count=1 | base64 - > /etc/scion/keys/master1.key
        mkdir /etc/scion/certs
        cp gen/trcs/* /etc/scion/certs
        mkdir -p /etc/scion/crypto/as
        cp ./gen/ASffaa_1_1/crypto/as/* /etc/scion/crypto/as/


   .. note::

      The above script will distribute the SCION control-plane PKI keys/certificates to the ASes. Additionally, it will create the two symmetric keys *master0.key* and *master1.key* per AS, and store them in the AS's */etc/scion/keys/* directory. The symmetric key is used by the AS in the date plane to verify the MACs in the hop fields of a SCION path (header).


Step 3 - Create the directories for the support database files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To create the required directories for the support database files, execute the following command. Do this once per each AS.

.. code-block::

   mkdir /var/lib/scion


Step 4 - Copy over the configuration files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**TODO**


Step 5 - Start the services
~~~~~~~~~~~~~~~~~~~~~~~~~~~

You now have to start the services on each of the five ASes. Execute the following commands on each AS:

.. code-block::

   screen /usr/local/scion/router --config /etc/scion/br.toml
   screen /usr/local/scion/dispatcher --config /etc/scion/dispatcher.toml
   screen /usr/local/scion/control --config /etc/scion/cs.toml
   screen /usr/local/scion/daemon --config /etc/scion/sd.toml






.. _step3:

Making Sure the Environment Works
.................................

Introduction

Tasks

1. Do this
2. Do that


.. _step4:

Testing
.......


Introduction

Tasks

1. Do this
2. Do that