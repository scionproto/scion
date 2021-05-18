*****************
ISD CA Operations
*****************

.. highlight:: bash

Once a new ISD is established through the completion of a key signing ceremony,
certificates can be generated for the Certificate Authorities and ASes of
the ISD.

Trust within an ISD flows from the TRC. The TRC contains one or more Root Certificates,
which are used to sign new CA Certificates, which are in turn used to sign one or more AS
Certificates.

The process of creating new CA Certificates is described in section `CA Certificates`_.
The process of creating new AS Certificates is described in section `AS Certificates`_.

To follow the steps in this document, ``openssl`` version ``1.1.1d`` or later is
required.

.. _ca-cert:

CA Certificates
===============

CA Certificates in SCION are always signed by a Root Certificate, which is
contained in the TRC. Because the Root Certificate is usually owned by the same
entity that also acts as a CA, the entity is able to perform the signing step by
itself.


Creating the initial CA Certificate
-----------------------------------

The steps in creating a new CA Certificate are:

#. Define the configuration of the CA Certificate in accordance with
   :ref:`the SCION requirements <cp-ca-certificate>`.
#. Create a new key pair.
#. Create a Certificate Signing Request using the key pair.
#. Use the Root Key and the Certificate Signing Request to create the new CA Certificate.

The configuration is defined in a file. OpenSSL reads the file and creates a
certificate that is compatible with SCION. An example configuration file is
included below. Note that the file includes the text ``{{.ShortOrg}}``; this
text **must** be replaced with the shortname of your organization. For example,
if your organization name is **ExampleCorp**, the line should contain ``name =
ExampleCorp Secure CA Certificate``.

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE ca_conf START
   :end-before: LITERALINCLUDE ca_conf END

.. attention::

   SCION CA certificates have short lifetimes (a lifetime of 11 days is recommended).

Once the file is ready, the rest of the steps can be executed through a series
of ``openssl`` commands.

These commands contain must be configured using the following values:

- CA Certificate validity start date. Prior to this date, the certificate is
  not considered valid. To configure this, replace occurrences of ``$STARTDATE``
  with the date in ``YYYYMMDDHHMMSSZ`` notation. For example, June 24th, 2020 UTC
  at noon is formatted as ``20200624120000Z``.
- CA Certificate validity end date. After this date, the certificate is no
  longer valid. To configure this, replace occurrences of ``$ENDDATE`` with
  the desired date. This uses the same notation as the ``$STARTDATE``.
- Folder where the keys are contained. To configure this, replace ``$KEYDIR`` with the folder name.

.. note::

   Note that the commands below assume that the CA Key and Root Key are found in the
   ``$KEYDIR`` folder, and have the names ``cp-ca.key`` and ``cp-root.key``. If this
   is not the case, the commands should be adjusted with the proper key locations.

Finally, to create the CA certificate, run the commands below.

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE gen_ca START
   :end-before: LITERALINCLUDE gen_ca END
   :dedent: 4

After generating the certificate, check that the output is reasonable:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_ca START
   :end-before: LITERALINCLUDE check_ca END
   :dedent: 4

The signature algorithm must be ``ecdsa-with-SHA512``.

The certificate can be validated with with the ``scion-pki`` binary:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_ca_type START
   :end-before: LITERALINCLUDE check_ca_type END
   :dedent: 4

Updating CA certificates
------------------------

CA certificates should be periodically rolled over. A validity of 11 days with 4
days overlap between two CA certificates is recommended. The recommended
schedule is shown below::

       Su | Mo | Tu | We | Th | Fr | Sa | Su | Mo | Tu | We | Th | Fr | Sa | Su | Mo
    ... 1 |  1 |  1 |  1 |  1 |    |    |    |    |    |    |    |    |    |    |
          |  2 |  2 |  2 |  2 |  2 |  2 |  2 |  2 |  2 |  2 |  2 |    |    |    |
          |    |    |    |    |    |    |    |  3 |  3 |  3 |  3 |  3 |  3 |  3 |  3 ...

Always on Monday a CA certificate with a validity of 11 days is created and
enabled. This way there is an overlap period until Thursday with the previous CA
certificate. That should leave enough room to debug issues during the work week
and renewals never fall on a Weekend.

Because CA certificates are created by signing them with the Root certificate,
the process for creating future CA certificates is the same as the initial one.

To comply with custom security policies that dictate that a Root Key should sit
behind an air gap, multiple CA certificates can be pre-generated for the same
entity.

AS Certificates
===============

AS Certificates in SCION are always signed by a CA Certificate, which is in turn
signed by the Root Certificate contained in the TRC.

Because the entities applying for an AS certificate (the ASes) are sometimes different from
the CA entity signing the certificate (the CA), we separate the steps in this section
into two: the AS steps and the CA steps.

.. important::

   SCION Certificate Authorities are also SCION ASes. This means that every CA must also
   create an AS certificate for itself. In this specific case, the two entities in this
   section (the AS and the CA) are the same.

Creating the initial AS Certificate
-----------------------------------

The steps in creating a new AS Certificate are:

#. The AS defines the configuration of the AS Certificate in accordance with
   :ref:`the SCION requirements <cp-as-certificate>`.
#. The AS creates a new key pair.
#. The AS creates a Certificate Signing Request using the key pair.
#. (If the AS and CA are different entities) The AS sends the Certificate Signing Request to the CA.
#. The CA uses its CA Key and the Certificate Signing Request to create the new AS Certificate.
#. (If the AS and CA are different entities) The CA sends the AS Certificate back to the AS.

The configuration is defined in a file. OpenSSL reads the file and creates a
certificate that is compatible with SCION. An example configuration file is
included below. Note that the file includes the text ``{{.ShortOrg}}``; this
text **must** be replaced with the shortname of your organization. For example,
if your organization name is **ExampleCorp**, the line should contain ``name =
ExampleCorp Secure CA Certificate``.

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE as_conf START
   :end-before: LITERALINCLUDE as_conf END

.. attention::

   SCION AS certificates have short lifetimes (a lifetime of 3 days is recommended).

To create the key pair and certificate signing request (CSR), the AS then runs
the OpenSSL commands below. In these commands, replace ``$KEYDIR`` with the
folder where private keys should be stored:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE gen_as_as_steps START
   :end-before: LITERALINCLUDE gen_as_as_steps END
   :dedent: 4

If the AS and CA are different entities, the certificate signing request can
then be sent to a CA for signing.

This step is performed by an entity that is a CA in the ISD. The CA creates
the certificate using its private key and the certificate signing request
received from the AS. The CA must also define the following:

- CA Certificate validity start date. Prior to this date, the certificate is
  not considered valid. To configure this, in the command below replace
  occurrences of ``$STARTDATE`` with the date in ``YYYYMMDDHHMMSSZ`` notation.
  For example, June 24th, 2020 UTC at noon is formatted as ``20200624120000Z``.
- CA Certificate validity end date. After this date, the certificate is no
  longer valid. To configure this, in the command below replace occurrences of
  ``$ENDDATE`` with the desired date. This uses the same notation as the
  ``$STARTDATE``.

Additionally, the CA should set ``$KEYDIR`` to the folder in which the private
key file (the file is called ``cp-ca.key``, in this example) is stored.

To create the certificate, the CA runs:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE gen_as_ca_steps START
   :end-before: LITERALINCLUDE gen_as_ca_steps END
   :dedent: 4

After generating the certificate, check that the output is reasonable:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_as START
   :end-before: LITERALINCLUDE check_as END
   :dedent: 4

The signature algorithm must be ``ecdsa-with-SHA512``.

The certificate can be validated with with the ``scion-pki`` binary:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_as_type START
   :end-before: LITERALINCLUDE check_as_type END
   :dedent: 4

If the AS and CA are different entities, the CA should then send the certificate
back to the AS that request it.

Creating future AS certificates
-------------------------------

Because AS certificates are created by signing them with the CA certificate,
the process for creating future CA certificates is the same as the initial one.

In a running ISD, AS certificates are usually built automatically by the
SCION control plane.
