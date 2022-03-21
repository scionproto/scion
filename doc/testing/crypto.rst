********************
Cryptography Testing
********************

.. highlight:: text

This document describes how the cryptography related parts of SCION are tested.
Indirectly, the correct functionality of the cryptography related parts are
always tested when a SCION topology runs, as they are an integral prat of the
protocol. The tests described here additionally verify the functionality
directly.

.. note::

   All commands listed in this document assume that the project is properly set
   up (see :ref:`setting-up-the-development-environment`), and that the commands
   are run from the project root.

All-in-one
==========

To run all tests, execute the commands listed below::

    go test ./pkg/scrypto/cppki/...
    go test ./private/trust/...
    go test ./control/trust/...
    go test ./scion-pki/...

    ./scion.sh topology && ./scion.sh run && sleep 10
    ./bin/end2end_integration

    ./acceptance/ctl gsetup
    PYTHONPATH=. ./acceptance/ctl grun cert_renewal
    PYTHONPATH=. ./acceptance/ctl grun trc_update

Unit Tests
==========

The unit test suite ensures that basic functionality works as intended.

1. Control Service
------------------

The control service has a trust-related module at ``control/trust``. The
module is responsible for creating signers and signatures, drive the trust
engine, and handle certificate renewal requests.

To run the test suite, execute::

    go test -v ./control/trust/...

2. Trust Engine
---------------

The trust engine located at ``pkg/trust`` stores and fetches trust material
such as certificate chains and TRCs, and provides them during signature
verification.

To run the test suite, execute::

    go test -v ./pkg/trust/...

3. CP-PKI library
-----------------

The library ``pkg/scrypto/cppki`` is home to the trust material definitions
for the SCION control plane certificates and the TRC.

To run the test suite, execute::

    go test -v ./pkg/scrypto/cppki/...

4. scion-pki
------------

The scion-pki tool can be used to interact with SCION control plane trust
material. For example, it can verify TRC updates, or inspect the TRC contents in
a human readable form.

To run the test suite, execute::

    go test -v ./scion-pki/...

Acceptance Tests
================

The acceptance tests ensure that the different components work together as
intended. For each acceptance test, a small SCION topology is started and
the behavior of the system is examined.

1. Basic End-to-End
-------------------

This test starts a basic SCION topology with the necessary trust material, and
checks that end-to-end connectivity can be established.

To run the test suite, execute::

    ./scion.sh topology && ./scion.sh run && sleep 10
    ./bin/end2end_integration


2. Certificate Renewal
----------------------

This test verifies that the control service in a CA AS is capable of issuing
certificate chains correctly for its customer ASes. Furthermore, the test
verifies that the customer ASes successfully switch to the renewed certificate
chain and the control/data plane continues to work as expected.

To run the test suite, execute::

    ./acceptance/ctl gsetup
    PYTHONPATH=. ./acceptance/ctl grun cert_renewal

3. TRC update
-------------

This test verifies that TRC updates are announced in beaconing and the control
services fetch them properly.

To run the test suite, execute::

    ./acceptance/ctl gsetup
    PYTHONPATH=. ./acceptance/ctl grun trc_update

