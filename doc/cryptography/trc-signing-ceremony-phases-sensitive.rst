.. _trc-signing-ceremony-phases-sensitive:

**********************************************
TRC Signing Ceremony Phases - Sensitive Update
**********************************************

.. highlight:: bash

This documents outlines the steps each participant must go through when
participating in a TRC Signing Ceremony for a sensitive TRC Update.

This document is organized by role. Please only refer to the section pertaining
to your role.

This document assumes that the basic devices required by the ceremony are present:

- Formatted USB Flash Drive (FAT)
- Ceremony administrator's device
- Voting representative's device

Furthermore, it assumes that each participant has access to the predecessor TRC
and the therein contained certificates.

The script for each role is described in the following sections:

- :ref:`ceremony-administrator-role-sensitive-update`
- :ref:`voting-as-representative-role-sensitive-update`
- :ref:`witness-role-sensitive-update`

Prior to the start, the *ceremony administrator* assigns a short identifier
to each *voting representative*. This identifier will later be used in the
naming of certain files. For the purpose of this document, the names are assumed
to be ``zürich``, ``bern``, and ``geneva``. All parties are attending and want
to include new certificates that were previously not part of the predecessor
TRC. Also for the purpose of this document, ``bern`` is assumed to be a
Certificate Authority for the ISD

.. _ceremony-administrator-role-sensitive-update:

Ceremony administrator role
===========================

The ceremony administrator brings their own *ceremony representative's device*
to the ceremony. For readability, in this section we refer to this device simply
as the *device*.


Phase 1 - Exchange of Certificates
----------------------------------

As the first step, the *ceremony administrator* announces the ``TRCID`` and
``PREDID`` that are used for the rest of the signing ceremony. The values depend
on the serial number of the predecessor TRC for this signing ceremony. Both
variables should be in the form ``ISD<isd-id>-B1-S<serial-number>``.

The *ceremony administrator* shares the *USB flash drive* with
each *voting representative*, and waits for each *voting representative*
to copy the needed certificates.

The *ceremony administrator* clarifies that only the certificates that should be
included in the next TRC should be exchanged. This also covers certificates that
were part of the predecessor TRC and will still be part of the next TRC.

Furthermore, the *ceremony administrator* reminds participants that they need to
copy all certificates needed for the role of the entity they represent. For
those who are only voters, this means the *CP sensitive voting certificate* and
the *CP regular voting certificate*. For those who are also Certificate
Authorities in the ISD, the list of certificates includes the *CP root
certificate*.


When the *ceremony administrator* gets the back the *USB flash drive*, they
connect it to their *device*. They must first check that all required certificates are
contained on the drive.

For each certificate, the *ceremony administrator* displays the validity period
and checks that they cover the previously agreed upon TRC validity.

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE display_validity START
   :end-before: LITERALINCLUDE display_validity END

Further, checks that the signature algorithms are correct:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE display_signature_algo START
   :end-before: LITERALINCLUDE display_signature_algo END

And finally, checks that the certificates are of valid type:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE validate_certificate_type START
   :end-before: LITERALINCLUDE validate_certificate_type END

If the results of these checks are as expected, the *ceremony administrator*
computes the SHA256 sum for each certificate:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE certificates_digest START
   :end-before: LITERALINCLUDE certificates_digest END

Disconnect the *USB flash drive*, and give it back to the *voting representatives*.
Wait for each *voting representative* to download the certificates of the other
*voting representatives*.

Finally, show the SHA256 sums on the screen for the *voting representatives* to
see, and wait for them to confirm that the SHA256 sum is correct for every
certificate.

After every *voting representative* has confirmed that the SHA256 sums are correct,
announce that **Phase 1** has concluded. If there is a mismatch in any of the sums,
**Phase 1** needs to be repeated.

Phase 2 - Creation of TRC Payload
---------------------------------

Once all the certificates have been accounted for, the *ceremony administrator*
must create a TRC payload.

First, ask the *voting representatives* to confirm the ISD number of the ISD.
This value is implied by the predecessor TRC and will be used to fill in the
``{{.ISD}}`` variable below.

Second, ask the *voting representatives* for the description of the TRC. This
will be used to fill in the ``{{.Description}}`` variable below.

Third, ask the *voting representatives* to confirm the serial number. The
value will be used to fill in the ``{{.SerialNumber}}`` variable below.

Forth, ask the *voting representatives* for the grace period of the TRC. The value
will be used to fill the ``{{.GracePeriod}}`` variable below. Ensure that the
implications of the grace period are understood by all parties.

Fifth, ask the *voting representatives* for the AS numbers of the ASes that
will be core (these will be used to populate the ``{{.CoreASes}}`` variable in
the file below), and the AS numbers of the ASes that will be authoritative
(these will be used to populate the ``{{.AuthoritativeASes}}`` variable in the
file below).

Sixth, ask the *voting representatives* for the voting quorum of the next TRC
update. The value will be used to fill in the ``{{.VotingQuorum}}`` variable
below.

Seventh, ask the *voting representatives* which voters from the predecessor TRC
should take part in the voting process. The value will be used to fill the
``{{.Votes}}`` variable below. Votes contains a sequence of indices of the voting 
certificates in the predecessor TRC. To find the indices, you can use the ``scion-pki
trcs human`` command.

Last, ask the *voting representatives* for the validity period of the new TRC.
The value will be used to fill in the ``{{.NotBefore}}`` and ``{{.Validity}}``
variable below. The ``{{.NotBefore}}`` variable is represented as a UNIX
timestamp (seconds since Epoch January 1st, 1970 UTC, e.g. ``1621857600``
equals May 24th, 2021 UTC at noon). Ensure that the selected validity
period overlaps with the one of the predecessor TRC.

To highlight variable types, we include some examples. The format must include
the part after the ``=`` sign exactly as it is written (i.e., with the exact
same quoting, parentheses, etc.).

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE sensitive_payload_conf_sample START
   :end-before: LITERALINCLUDE sensitive_payload_conf_sample END

.. note::

   The UNIX timestamp can be displayed in human readable form using the ``date``
   command::

       date -d @1621857600 --utc

   To compute the UNIX timestamp for a given date in UTC, use::

       date -d 'YYYY-MM-DD HH:MM:SSZ' +"%s"

Create the TRC payload configuration:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE sensitive_payload_conf START
   :end-before: LITERALINCLUDE sensitive_payload_conf END

Display the payload template file with the variables filled-in on the *device*
monitor. The *voting representatives* should compare the contents of the file
with their answers to the previous questions, to ensure that all the data is
correct.

Once the data has been verified, compute the DER encoding of the TRC data:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE create_payload START
   :end-before: LITERALINCLUDE create_payload END

Compute the SHA256 sum of the TRC payload file using:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE payload_digest START
   :end-before: LITERALINCLUDE payload_digest END

Connect the *USB flash drive* to your device, and copy the TRC payload file to
the root directory, then disconnect the *USB flash drive*. Hand out the *USB flash drive*
to the *voting representatives*.

The *voting representatives* proceed to check the contents of the TRC payload
file by computing the SHA256 sum. Over the duration of the checks, keep the
SHA256 sum of the file available on the monitor for inspection.

This phase concludes once every *voting representative* confirms that the
contents of the TRC payload are correct. Once that happens, announce that
**Phase 2** has successfully concluded.

Phase 3 - Signing of the TRC Payload
------------------------------------

This phase consists of the *voting representatives* casting votes on the TRC
payload file. Furthermore, all *voting representatives* that include a
previously not included certificate must show proof-of-possession, i.e., show
that they have access to the private key listed in these fresh certificates.
This is done by signing the TRC with the respective private key. The phase
concludes after all *voting representatives* have cast their votes, the
applicable parties have shown proof-of-possession, and copied the resulting
signatures onto the *USB flash drive*.

As part of this phase, the *voting representatives* inspect the TRC payload.
Display the TRC payload using:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE display_payload START
   :end-before: LITERALINCLUDE display_payload END
   :dedent: 4

Walk the *voting representatives* through the output and describe the meaning
and implications of each part.

Once every *voting representative* has finished the signing process, announce
that **Phase 3** has successfully concluded.

Phase 4 - Assembly of the TRC
-----------------------------

This phase consists of assembling the final TRC by aggregating the payload data with
the votes and proof-of-possessions (signatures) cast by the *voting representatives*.

Connect the *USB flash drive* to the *device*. Given the example data, the votes
should be available at the following locations on the *USB flash drive*:

- ``/bern/isd.sensitive.vote.trc``
- ``/geneva/isd.sensitive.vote.trc``
- ``/zürich/isd.sensitive.vote.trc``

The proof-of-possessions for the freshly included certificates should be available
at the following locations on the *USB flash drive*:

- ``/bern/isd.sensitive.trc``
- ``/bern/isd.regular.trc``
- ``/geneva/isd.sensitive.trc``
- ``/geneva/isd.regular.trc``
- ``/zürich/isd.sensitive.trc``
- ``/zürich/isd.regular.trc``

To assemble the final TRC in a file, run the following command:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE combine_payload START
   :end-before: LITERALINCLUDE combine_payload END

To check that the resulting TRC is correct, run:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE verify_payload START
   :end-before: LITERALINCLUDE verify_payload END

Copy the signed TRC to the *USB flash drive* in the root directory. Disconnect
the *USB flash drive*.

Finally, compute the SHA256 sum of the final TRC:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE trc_digest START
   :end-before: LITERALINCLUDE trc_digest END

and keep it for reference on the monitor of the *device*.

Each *voting representative* now checks that the final TRC contains the correct
data, and that it can be verified. Wait for each *voting representative* to
confirm that verification has finished successfully. If any verification fails,
**Phase 3** and **Phase 4** need to be repeated.

Furthermore, the *voting representatives* inspect that all signatures are present.
Display the signed TRC with this command:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE trc_content START
   :end-before: LITERALINCLUDE trc_content END

Walk the *voting representatives* through the output and describe the meaning
and implications of each part.

If each *voting representative*
confirms they have successfully verified the TRC, announce that **Phase 4** has
finished successfully. Then, announce that the key signing ceremony has
concluded successfully.

.. _voting-as-representative-role-sensitive-update:

Voting AS representative role
=============================

Each voting representative brings their own *voting representative's device* to
the ceremony. Each voting representative performs actions only on their own
device. For readability, in this section we refer to this device simply as the
*device*.

Preparation
-----------

To follow the commands described in the following sections, four environment
variables need to be set up:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE export_paths_update START
   :end-before: LITERALINCLUDE export_paths_update END
   :dedent: 4

The ``TRCID`` and ``PREDID`` variables that are used are announced by the
*ceremony administrator* in the beginning of the signing ceremony.

To verify the resulting TRC with openssl, sensitive voting certificates
of the predecessor TRC must be available as PEM bundle.

To cast a vote, the *voting representatives* needs access to the sensitive
voting certificate that is part of the predecessor TRC and its private key. For
the remainder of this document, the private key is assumed to be accessible at
``$KEYDIR/$PREDID/sensitive-voting.key`` and the certificate at
``$PUBDIR/$PREDID/sensitive-voting.crt``.

Furthermore, everything that is copied from the *USB Flash Drive* should be
put in the current working directory.

.. important::

   It is required that the machine used to execute the commands has openssl
   version 1.1.1d or higher installed.

Phase 1 - Exchange of Certificates
----------------------------------

Phase 1 consists of sharing the self-signed voting and root certificates that
should be included in the TRC.

Plug the *USB Flash Drive* into the *device*.

Create a new folder; use the identifier you received from the *ceremony
administrator* as the name of the folder (e.g., if the identifier is ``zürich``,
the folder will have the same name).

Copy the *CP Sensitive Voting Certificate* and the *CP Regular Voting Certificate*
onto the *USB Flash Drive* into the newly created folder. The sensitive voting
certificate should be named ``sensitive-voting.crt``, and the regular voting
certificate should be named ``regular-voting.crt``.

.. Warning::

   Note that only the certificates must be shared during the step, not the private
   keys. Copying a private key by mistake invalidates the security of the ceremony.

If the entity you represent will also act as a CA in the ISD, also copy the *CP
Root Certificate* to the *USB flash drive*. The file should be named
``cp-root.crt``.

Disconnect the *USB flash drive* from the *device*, and pass it to the next *voting
representative* or, if certificate copying has concluded, to the *ceremony administrator*.

Wait for the *ceremony administrator* to pass back the *USB flash drive*.
Connect the *USB flash drive* to the *device*, and copy the folders with the
certificates of the **other** *voting representatives*.
Disconnect the *USB flash drive*.

Wait for the *ceremony administrator* to announce the SHA256 sums for each
certificate. For each certificate, check carefully that the SHA256 sum announced
by the administrator matches the value computed on your copy of the certificate.

To compute the SHA256 on a Linux host, run the following commands from the
folder that contains the copied files.

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE certificates_digest START
   :end-before: LITERALINCLUDE certificates_digest END

Furthermore, check that the certificate that is on the *USB flash drive* does
not differ from your own. For example, for identifier ``bern``, the command that should
be executed in the same folder as above is:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE diff_own_cert START
   :end-before: LITERALINCLUDE diff_own_cert END

Phase 1 concludes once every participant confirms that the *ceremony administrator* has
the correct version of each certificate (that is, every SHA256 sum matches).

Phase 2 - Creation of TRC Payload
---------------------------------

In this phase, please answer the following questions asked by the *ceremony administrator*:

- What text description should the TRC contain? (e.g., "Swiss Medical ISD")
- What is the grace period?
- Who will be the core ASes of the ISD?
- Who will be the authoritative ASes of the ISD?
- Who will vote for the TRC update?

.. .. warning::

   If ``no_trust_reset`` is set to true, all relying parties will reject any
   trust reset. This means that no new TRC update chain can be established. All
   TRC updates from this point forward will be rooted in this ceremony's base
   TRC. This closes the door for recovery from catastrophic key compromise, and
   is strongly discouraged.

If the answers from all *voting representatives* do not exactly match,
discussions are allowed to reach a common answer. If consensus cannot be
reached for a question, the ceremony is voided and no TRC is created.

After the *ceremony administrator* has collected all answers, they will produce a file
detailing TRC contents. Inspect the contents of the file carefully on the *ceremony
administrator*'s monitor, and point out any mistakes. If this verification succeeds,
the *ceremony administrator* will hand out the *USB flash drive*, which now contains the
TRC data.

Plug the *USB flash drive* into your device, copy the TRC file (it should be in the root
directory, called ``$TRCID.pld.der``) to your device, and disconnect
the *USB flash drive*. Compute the SHA256 sum on the file by executing the following command
from the folder that contains the copied file:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE payload_digest START
   :end-before: LITERALINCLUDE payload_digest END

Compare the result of the command with the SHA256 sum displayed on the monitor of the
*ceremony administrator*. If there are any differences, this phase needs to be restarted.

This phase concludes once all *voting representatives* confirm that the
``$TRCID.pld.der`` file has the correct digest.

Phase 3 - Signing of the TRC Payload
------------------------------------

This phase consists of signing the TRC file. Two signatures need to be computed,
one using the *regular voting certificate* and one using the *sensitive voting certificate*.

Before signing, check that the TRC payload is sound:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE display_payload START
   :end-before: LITERALINCLUDE display_payload END
   :dedent: 4

To compute the proof-of-possession signatures, run:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE sign_payload START
   :end-before: LITERALINCLUDE sign_payload END
   :dedent: 4

To compute the vote, run:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE sensitive_vote START
   :end-before: LITERALINCLUDE sensitive_vote END
   :dedent: 4

.. Warning::

   The above operations requires access to the private key. If this key gets leaked, it may
   compromise the security of the ISD. Make sure no other operations read this key.

To sanity check that the proof-of-possession signatures were created correctly, run:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_signed_payload START
   :end-before: LITERALINCLUDE check_signed_payload END
   :dedent: 4

To sanity check that the vote was cast correctly, run:

.. literalinclude:: crypto_lib.sh
   :start-after: LITERALINCLUDE check_sensitive_vote START
   :end-before: LITERALINCLUDE check_sensitive_vote END
   :dedent: 4

Connect the *USB flash drive* to the *device*, and copy ``$TRCID.regular.trc``,
``$TRCID.sensitive.trc``, and ``$TRCID.sensitive.vote.trc`` to the folder named
after your identifier.

Disconnect the *USB flash drive*, and hand it to the other *voting representatives*.

Phase 4 - Assembly of the TRC
-----------------------------

This phase starts with the *ceremony administrator* aggregating the TRC payload and the votes.

Once the aggregation is finished, the *USB flash drive* will contain the final TRC.

Connect the *USB flash drive* to the *device*, and copy the ``$TRCID.trc`` file located in
the root of the *USB flash drive*.

Compute the SHA256 sum by navigating to the folder that contains the TRC file
and executing the following command:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE trc_digest START
   :end-before: LITERALINCLUDE trc_digest END

Compare the result with what is displayed on the monitor of the *ceremony administrator*.
If the sum differs, then **Phase 3** and **Phase 4** need to be repeated.

Next, check that all the fields are consistent with earlier choices. To print the fields
that are present in the TRC, run:

.. literalinclude:: trc_ceremony_sensitive.sh
   :start-after: LITERALINCLUDE trc_content_rep START
   :end-before: LITERALINCLUDE trc_content_rep END
   :dedent: 4

If there is a mismatch between any of the fields and the desired policy, then
**Phase 3** and **Phase 4** need to be repeated.

As a final check, verify that the signature information of each signature is present; there
should be one signature for each *voting representative* that voted, and one
signature for each sensitive or regular voting certificate that was previously
not part of the predecessor TRC. If a signature is missing, then **Phase 3** and
**Phase 4** need to be repeated.

Inform the *ceremony administrator* of the outcome of the verification.

.. _witness-role-sensitive-update:

Witness role
============

The role of the witness is to examine that the rules in this document are
followed by the participants. While not strictly required, it is useful if a
witness is familiar with the steps that both the *ceremony administrator* and
*voting representatives* must perform.

The witness has no active role in any of the steps of the ceremony, but can stop
the process and inquire for more information if they feel the integrity of the
process might have been compromised.

The witness should also be aware of what phase the ceremony is in, and take
notes on which phases completed successfully.
