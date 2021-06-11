**************************************
TRC Signing Ceremony Preparation Steps
**************************************

.. highlight:: bash

Each party involved in a TRC signing ceremony must go through a few steps in
preparation for the ceremony. This document outlines these steps.

.. important::

   It is required that the machine used to execute the commands has openssl
   version 1.1.1d or higher installed.

.. note::

   **Placeholders**

   This document contains placeholders for certificate configurations.
   Placeholders look like this ``{{.Property}}``. These placeholders need to be
   filled before executing the commands.

Ceremony administrator role
===========================

The ceremony administrator should send out the high-level
:doc:`trc-signing-ceremony` description, the appropriate TRC Signing Ceremony
Phases document, and this document all in digital form to the participants.

The existing TRC Signing Ceremony Phases documents are listed here:

* :ref:`trc-signing-ceremony-phases-base`
* :doc:`trc-signing-ceremony-phases-sensitive`

Furthermore, the ceremony administrator should remind all voters that they need
to agree on a common TRC policy before scheduling the TRC ceremony. Importantly,
the TRC validity period should be agreed upon, such that every voter can
generate certificates that cover the full validity.

The ceremony administrator should bring all digitally distributed documents as a
print out for all parties that take part.

Voting AS representative roles
==============================

.. important::

   All voters need to agree on a preliminary TRC policy. Especially, the
   **validity period** of the TRC, since **all** the generated certificates must
   cover the **full TRC validity period**. The other policy values can be
   amended during the ceremony itself.

When the preliminary policy is in place. The voters can start generating the
necessary certificates.

Create a safe workspace folder
------------------------------

To protect the key material, we recommend using an air-gapped workstation. Next,
a folder for key material and for certificates is created. First navigate to
the desired parent directory (.e.g. ``cd /home/user``).

To create the folders:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE set_dirs START
   :end-before: LITERALINCLUDE set_dirs END
   :dedent: 4

.. note::

   For traceability, we recommend that each action in the public directory is
   committed to git.


Create basic configuration
--------------------------

Navigate to the public directory:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE navigate_pubdir START
   :end-before: LITERALINCLUDE navigate_pubdir END
   :dedent: 4

This directory stores the openssl configurations, the CSRs and the created
certificates. To avoid duplicated information, create a ``basic.cnf`` that can
be imported from the sensitive voting, regular voting and root certificate
configuration files:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE basic_conf START
   :end-before: LITERALINCLUDE basic_conf END

Fill in the required fields.

.. note::

   The ``{{.Country}}`` must be replaced with an ISO 3166-1 alpha-2 code.
   Switzerland, for example, has the code ``CH``.

To set the start and end time of a X509 certificate using openssl, the ``ca``
command is necessary. The directory needs to be prepared:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE prepare_ca START
   :end-before: LITERALINCLUDE prepare_ca END
   :dedent: 4


Sensitive voting
----------------

This step creates a sensitive voting key and certificate.

.. note::

   The ISD-AS configuration field is optional, but should be provided if the
   party has an AS identifier, the ISD number must match with the TRC this
   certificate will be used in.

First, create the sensitive voting certificate configuration. In the file,
replace ``{{.ShortOrg}}`` with the name of your organization:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE sensitive_conf START
   :end-before: LITERALINCLUDE sensitive_conf END

.. note::

   Make sure the **common name** is **different** for each certificate type. The
   proposed name makes it easier for human operators to reason about what the
   the purpose of the certificate is.

.. important::

   If this step is executed in preparation for a TRC update signing ceremony,
   make sure that the previous private key and certificate are not overwritten.

   For example, you can version the predecessor private key and certificate by
   running the following command:

   .. literalinclude:: crypto_lib.sh
      :start-after: LITERALINCLUDE version_sensitive START
      :end-before: LITERALINCLUDE version_sensitive END
      :dedent: 4


Using this configuration, create the sensitive voting key and certificate. The
start and end date need to be replaced with the time when the certificate
becomes valid, and the time when it expires. The format is ``YYYYMMDDHHMMSSZ``.
For example, June 24th, 2020 UTC at noon, is formatted as ``20200624120000Z``.
The required commands are:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE gen_sensitive START
   :end-before: LITERALINCLUDE gen_sensitive END
   :dedent: 4

After generating the certificate, check that the output is reasonable:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_sensitive START
   :end-before: LITERALINCLUDE check_sensitive END
   :dedent: 4

The validity time must cover the agreed upon TRC validity period. The
signature algorithm must be ``ecdsa-with-SHA512``.

The certificate can be validated with with the ``scion-pki`` binary:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_sensitive_type START
   :end-before: LITERALINCLUDE check_sensitive_type END
   :dedent: 4

Regular voting
--------------

This step creates a regular voting key and certificate.

.. note::

   The ISD-AS configuration field is optional, but should be provided if the
   party has an AS identifier, the ISD number must match with the TRC this
   certificate will be used in.

Create the regular voting certificate configuration:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE regular_conf START
   :end-before: LITERALINCLUDE regular_conf END

.. note::

   Make sure the **common name** is **different** for each certificate type. The
   proposed name makes it easier for human operators to reason about what the
   the purpose of the certificate is.

.. important::

   If this step is executed in preparation for a TRC update signing ceremony,
   make sure that the previous private key and certificate are not overwritten.

   For example, you can version the predecessor private key and certificate by
   running the following command:

   .. literalinclude:: crypto_lib.sh
      :start-after: LITERALINCLUDE version_regular START
      :end-before: LITERALINCLUDE version_regular END
      :dedent: 4

Using this configuration, create the regular voting key and certificate. The
start and end date need to be replaced with the time when the certificate
becomes valid, and the time when it expires. The format is ``YYYYMMDDHHMMSSZ``.
For example, June 24th, 2020 UTC at noon, is formatted as ``20200624120000Z``.
The required commands are:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE gen_regular START
   :end-before: LITERALINCLUDE gen_regular END
   :dedent: 4

After generating the certificate, check that the output is reasonable:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_regular START
   :end-before: LITERALINCLUDE check_regular END
   :dedent: 4

The validity time must cover the agreed upon TRC validity period. The
signature algorithm must be ``ecdsa-with-SHA512``.

The certificate can be validated with with the ``scion-pki`` binary:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_regular_type START
   :end-before: LITERALINCLUDE check_regular_type END
   :dedent: 4

CP Root
-------

This step creates a CP root key and certificate.

.. note::

   This step only has to be executed by issuing ASes.

Create the CP root certificate configuration:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE root_conf START
   :end-before: LITERALINCLUDE root_conf END

.. note::

   Make sure the **common name** is **different** for each certificate type. The
   proposed name makes it easier for human operators to reason about what the
   the purpose of the certificate is.

.. important::

   If this step is executed in preparation for a TRC update signing ceremony,
   make sure that the previous private key and certificate are not overwritten.

   For example, you can version the predecessor private key and certificate by
   running the following command:

   .. literalinclude:: crypto_lib.sh
      :start-after: LITERALINCLUDE version_regular START
      :end-before: LITERALINCLUDE version_regular END
      :dedent: 4

Using this configuration, create the CP root key and certificate. The start and
end date need to be replaced with the time when the certificate becomes valid,
and the time when it expires. The format is ``YYYYMMDDHHMMSSZ``. For example,
June 24th, 2020 UTC at noon, is formatted as ``20200624120000Z``. The required
commands are:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE gen_root START
   :end-before: LITERALINCLUDE gen_root END
   :dedent: 4

After generating the certificate, check that the output is reasonable:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_root START
   :end-before: LITERALINCLUDE check_root END
   :dedent: 4

The validity time must cover the agreed upon TRC validity period. The
signature algorithm must be ``ecdsa-with-SHA512``.

The certificate can be validated with with the ``scion-pki`` binary:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_root_type START
   :end-before: LITERALINCLUDE check_root_type END
   :dedent: 4
