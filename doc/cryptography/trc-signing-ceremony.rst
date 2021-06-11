.. _trc-ceremony:

********************
TRC Signing Ceremony
********************

The TRC contains policy information about an ISD and acts as a distribution
mechanism for the trust anchors of that TRC. It enables securing the control
plane interactions, and thus is an integral part of the SCION infrastructure.

In the signing ceremony, the voters of the ISD meet in person to sign an agreed
upon TRC. As part of the ceremony, the public keys of all voters are exchanged.

There are two types of signing ceremonies: the ceremony to sign the **base TRC** and
the ceremony to sign a **non-base TRC**.

The **base TRC** builds the anchor point for a TRC update chain. All voters need to
take part in this ceremony. The very first TRC for an ISD number, the **initial
TRC**, is a special case of the base TRC where the ISD number is chosen. Future
base TRCs are only created in **trust resets**, which are a disaster recovery
procedure for catastrophic scenarios where the air-gapped high security keys of
multiple voting members of the ISD have been simultaneously compromised. The likelihood
of such a compromise is extremely low if keys are adequately stored.

A **non-base TRC** is the result of a TRC update. Only a quorum of voters need to
partake in a non-base TRC signing ceremony.

Ceremony Participants
=====================

A signing ceremony typically includes participants from various organizations. For example,
a signing ceremony might include something like the following:

- Ceremony Administrator:

  - Giraffe Example Organization

- Voting AS Representatives:

  - Elephant Example Organization
  - Gorilla Example Organization
  - Zebra Example Organization

- Witnesses

The **Ceremony Administrator** is in charge of moderating the whole signing
process, and walks all participants through the steps they need to execute and
acts as the information sharing hub between them.

The **Voting AS Representative** is capable of creating voting signatures on the
TRC. This means the voting representative is in possession of a device with the
private keys of the respective certificates in the TRC.

The **Witness** is any person that participates in the ceremony as a passive
entity. They observe the ceremony execution.

Ceremony Preparations
=====================

Prior to the ceremony, participants decide on the physical **location** of the
ceremony, the **devices** that will be used during the ceremony and the
**policy** of the ISD.

Location
--------

The location must provide electricity and enough power sockets for each
participant. Furthermore, it should provide a monitor (or projector) that allows
the ceremony administrator to screen cast.

Devices
-------

Each party brings their own device that is provisioned with the required
material, as described below.

- **USB Flash Drive**:
  For exchanging data, a USB flash drive is used. It should be formatted as
  FAT32 before starting the ceremony. The drive can either be provided by
  ceremony administrator, or, if preferable, by any of the voting
  representatives.

- **Ceremony Administrator's Device**:
  The ceremony administrator should bring a machine that is capable of creating
  and verifying a TRC. Furthermore, it needs to be able to compute the SHA-512
  digest of files.

- **Voting Representative's Device**:
  The voting representative should bring a machine that is capable of signing
  and verifying TRCs. Thus, the machine needs to have access to all the voting
  private keys. Furthermore, it needs to be able to compute the SHA-512 digest
  of the files. The exact binaries that are required are described in a separate
  document.

Policy
------

The voting entities need to agree on the ISD policy, before the ceremony can be
executed. Specifically, they need to agree on:

- Validity of the TRC
- Grace period (except for base TRCs)
- Voting Quorum
- Core ASes
- Authoritative ASes
- Description
- List of CP Root Certificates

When these values are agreed upon, a quorum of voters needs to execute the
signing ceremony. The set of needed keys depends on whether a base TRC, or a TRC
update is signed. For the base TRC, all voting entities need to be present with
both their sensitive and regular voting key.

Ceremony Process
================

The ceremony process is structured in multiple rounds of data sharing. The
ceremony administrator leads the interaction and instructs each participant with
what to do.

Phase 1: Certificate Exchange
-----------------------------

All entities share the certificates they want to be part of the TRC with
ceremony administrator, who aggregates and bundles them. The bundle is then
shared with all voters.

The ceremony administrator displays the SHA-512 digest of each bundled
certificate on the monitor. Each voting representative verifies that the
certificates they contributed have the same hash as what is displayed on the
monitor. Further, all voting representatives confirm that the bundled
certificates on their machine all have matching hashes.

Phase 2: TRC Payload Creation
-----------------------------

The ceremony administrator generates the TRC based on the bundled certificates
and the agreed upon ISD policy. The result is displayed on the monitor along
with a SHA-512 digest. The TRC is distributed to all voting representatives. All
of them must verify that the hash matches.

Phase 3: TRC Signing
--------------------

Each voting representative attaches a signature for each of their new voting
certificate to the TRC. When signing a non-base TRC, the voting representatives
further cast a vote with the voting key present in the last TRC.

Phase 4: TRC Assembly
-----------------------

All voting representatives share the signed TRC with the ceremony administrator,
who aggregates them in a single signed TRC file. The signed TRC is validated by
inspecting its contents on the monitor and verifying the signatures based on the
exchanged certificates in phase 1.

The ceremony administrator then shares the signed TRC with all participants.
Each of them must then inspect it once more, and verify it based on the
certificates exchanged in phase 1.

At this point, the ceremony is concluded. All participants have the signed TRC,
and can use it to distribute the trust anchors for their ISD.

Security Model
==============

For this ceremony, we assume that all parties are trustworthy. Issues
encountered during the ceremony are assumed to be caused by honest mistakes, and
not by malicious intent. To counter mistakes, we include hash comparison checks,
such that every participant is sure that they operate on the same data.

Furthermore, the private keys of each participants never leave their machine.
The ceremony administrator does not have to be entrusted with private keys.

