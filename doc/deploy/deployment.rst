.. _deployment-guide:

Setting Up a Demo Environment
=============================

This document helps you set up a SCION demo environment, which consists of a stand-alone full-scale environment distributed among five computers.


Setup
-----


Sample SCION Setup
..................

This is the sample setup:

======================= ==== ========= ======== =============
DNS Name                ISD  AS        Purpose  Notes
======================= ==== ========= ======== =============
scion01.martincoit.net  42   ffaa:1:1  Core
scion02.martincoit.net  42   ffaa:2:1  Core
scion04.martincoit.net  42   ffaa:3:1  Core
scion05.martincoit.net  42   ffaa:1:1  Leaf
scion06.martincoit.net  42   ffaa:2:1  Leaf
======================= ==== ========= ======== =============

*Table 1: Sample setup*


Sample SCION Topology
.....................

The SCION topology looks like this:

https://app.diagrams.net/#G1WWprufQyCWXVKGZ5z5m_fIQyzTYcnNFk



.. _prerequisites:

Prerequisites
-------------

There are some prerequisites before you can start setting up your demo environment. These are listed here:


- 5 VMs - **Ubuntu** 22.04.3 LTS (Jammy Jellyfish). For more information, see  `Ubuntu Jammy Jellyfish <https://releases.ubuntu.com/jammy/>`_.
- Memory? CPU?
- Network interfaces? (just one?)
- OS Configuration?

  - User accounts?
  - System accounts?



Steps to Perform
----------------

To create this environment, you need to perform the following steps, in this order:

- Step 1: Installation  (:ref:`step1`)
- Step 2: Configuration  (:ref:`step2`)
- Step 3: Making sure the environment works (:ref:`step3`)
- Step 4: Testing (:ref:`step4`)


The following sections explain the required steps, one section per step.



.. _step1:

Installation
............

This section guides you through the installation of the SCION software.

First, you need to get the SCION software. You have two options:

- Install from packages (coming later in 2024).
- Install from binaries. The latest software can be found at:

  - `Latest official release <https://github.com/scionproto/scion/releases/>`_
  - `Latest nightly build <https://buildkite.com/scionproto/scion-nightly/builds/latest/>`_


In this example, we use the following official release version:
*scion_v0.9.1_amd64_linux.tar.gz*


1. Download and extract the latest scionproto binary release by executing the following command:

.. code-block::

wget https://github.com/scionproto/scion/releases/download/v0.9.1/scion_v0.9.1_amd64_linux.tar.gz
tar -xzvf scion_v0.9.1_amd64_linux.tar.gz


2. You can now install the selected software packages by executing a couple of commands.
AS #1 Core
The first machine will be AS #1
Sudo -i
Cd /tmp
wget https://github.com/scionproto/scion/releases/download/v0.9.1/scion_v0.9.1_amd64_linux.tar.gz
Mkdir /usr/local/scion
Cd /usr/local/scion
tar xfz /tmp/scion_v0.9.1_amd64_linux.tar.gz




.. _step2:

Configuration
.............

Introduction

Tasks

1. Do this
2. Do that


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