.. _drkey:

**************************************************
Dynamically Recreatable Key (DRKey) Infrastructure
**************************************************

This document presents the design for the Dynamically Recreatable Key (DRKey)
infrastructure.

Overview
========
The DRKey protocol enables routers and end hosts to derive cryptographic
symmetric keys on the fly from a single local secret.

DRKey is used for the following systems:

- SCION Packet Authenticator Option (SPAO)
- COLIBRI
- EPIC

In the DRKey system, the key establishment is offloaded to the Control Service
(CS).
Control services exchange top-level keys that will be used afterwards
to derive lower level keys locally.
The DRKey system leverages efficient key derivation and pseudorandom functions
to derive keys in the hierarchy from top to bottom.

The first secret in the hierarchy (:math:`SV_A`) is derived from a long-term ``master_secret``,
using a key derivation function.
For the rest of the derivations, DRKey utilizes pseudorandom functions, which are more efficient.
Informally, key derivation functions output a cryptographic key indistingushible from
a random key if the secret is unknown for the attacker.
In contrast, the security of pseudorandom functions relies on the input being a uniformly
random secret.

Notation
========

.. list-table::
   :widths: 50 50
   :header-rows: 1

   * - Notation
     - Description
   * - :math:`KDF_{K}(X)`
     - key derivation function using key K and taking X as an input
   * - :math:`PRF_K (X)`
     - pseudorandom function using key K and taking X as an input
   * - :math:`A`
     - Autonomous system (identified by the pair ISD and AS number)
   * - :math:`H_A`
     - end host (identified by its address)
   * - :math:`CS_A`
     - Control service located in AS A
   * - :math:`SV_A`
     - AS A's local secret value


Derivation scheme
=================

We define two types of derivation: the :ref:`drkey-specific-derivation` derivation and
the :ref:`drkey-generic-derivation`. Both of them leverage the 4-level derivation scheme.

4-level derivation
------------------

**Secret value (Level 0)**

Each AS locally derives one :math:`SV_A^{protocol}` per protocol and epoch. This secret value
is renewed at every epoch and it is only shared with trustworthy entities that require
to derive keys on the fly for the specified protocol.

**AS-AS (Level 1)**

The ``AS-AS`` key is derived locally in the AS :math:`A` CS (:math:`CS_A`) and exchanged
with remote CS. More specifically :math:`CS_A` shares :math:`K_{A,B}` with
:math:`CS_B`.

**host-AS (Level 2)**

The ``host-AS`` key is derived using the Level 1 symmetric key.
It is intended to be used as an intermediate derivation allowing the node holding this
key to derive Level 3 keys locally.
Therefore, the key :math:`K_{A:H_A,B}` is only available to :math:`A:H_A` and trusted
infrastructure.

.. _drkey-as-host:

**AS-host (Level 2)**

The ``AS-host`` key is also derived using the Level 1 symmetric key,
however this key is intended to be used for communication.
In this case, the key :math:`K_{A,B:H_B}` is shared between :math:`AS_A` trusted nodes
and :math:`B:H_B`.

.. _drkey-host-host:

**host-host (Level 3)**

The ``host-host`` key is derived in :math:`H_A` and :math:`CS_B` using the ``host-AS`` key. This key
is available to both hosts :math:`H_A` and :math:`H_B`.

.. _drkey-specific-derivation:

Protocol-specific derivation
----------------------------

.. list-table::
   :widths: 50 100 50
   :header-rows: 1

   * - Identifier
     - Derivation
     - Name
   * - :math:`SV_A^{protocol}`
     - :math:`KDF(input)`
     - Secret value (Level 0)
   * - :math:`K_{A,B}^{protocol}`
     - :math:`PRF_{SV_A^{protocol}}(type||B)`
     - AS-AS key (Level 1)
   * - :math:`K_{A,B:H_B}^{protocol}`
     - :math:`PRF_{K_{A,B}^{protocol}}(type||len/type(H_B)||H_B)`
     - AS-host key (Level 2)
   * - :math:`K_{A:H_A,B}^{protocol}`
     - :math:`PRF_{K_{A,B}^{protocol}}(type||len/type(H_A)||H_A)`
     - host-AS key (Level 2)
   * - :math:`K_{A:H_A,B:H_B}^{protocol}`
     - :math:`PRF_{K_{A:H_A,B}^{protocol}}(type||len/type(H_B)||H_B)`
     - host-host key (Level 3)

The SV computation is local, thus the AS is free to compute it as desired as long as
it outputs a cryptographic key indistingushible from a random key for an attacker.
We suggest to use the *PBKDF2* as KDF function and set ``input`` to:
``input = "len(master_secret) || master_secret || protocol || epoch_begin || epoch_end"``.

The key notation states for which entity the key derivation must be efficient.
The term in the left identifies the key *issuer* (the fast side in the derivation),
whereas the right term identifies the key *subject* (the slow side in the derivation).
For example, :math:`K_{A,B:H_B}` can be used in both communication directions,
but it is directly derivable by :math:`AS_A`, whereas the :math:`AS_B` requires to contact
:math:`CS_A` to fetch the intermediate Level 1 key.

.. _drkey-generic-derivation:

Generic-protocol derivation
---------------------------

.. list-table::
   :widths: 50 50 50
   :header-rows: 1

   * - Identifier
     - Derivation
     - Name
   * - :math:`SV_A`
     - :math:`KDF(input)`
     - Secret value (Level 0)
   * - :math:`K_{A,B}`
     - :math:`PRF_{SV_A}(type||B)`
     - AS-AS key (Level 1)
   * - :math:`K_{A,B:H_B}^{protocol}`
     - :math:`PRF_{K_{A,B}}(type||protocol||len/type(H_B)||H_B)`
     - AS-host key (Level 2)
   * - :math:`K_{A:H_A,B}^{protocol}`
     - :math:`PRF_{K_{A,B}}(type||protocol||len/type(H_A)||H_A)`
     - host-AS key (Level 2)
   * - :math:`K_{A:H_A,B:H_B}^{protocol}`
     - :math:`PRF_{K_{A:H_A,B}^{protocol}}(type||len/type(H_B)||H_B)`
     - host-host key (Level 3)

This derivation scheme allows applications to define "niche" protocols. By including
the protocol in the Level 2 derivation input.

PRF derivation specification
----------------------------

type
    1 byte field identifying the derivation type (``AS-AS``, ``AS-host``,
    ``host-AS`` and ``host-host``). This enables domain separation among computed
    keys. For instance, it outputs (with high probability)
    :math:`K_{A:H_A,B} ≠ K_{A,B:H_B}` when :math:`H_A==H_B`.

protocol
    2 byte field used in the PRF derivation for Lvl2 generic-protocol derivations
    to identify the concrete protocol.

ISD-AS address
    This field is present in Lvl1 derivations and follows the format in
    :ref:`SCION Address Header <scion-address-header>`.

host length/type
    This field is present in Lvl2/3 derivations and follows the format for the DT/DL
    field in :ref:`SCION Common Header <scion-common-header>`.

host address
    This field is present in Lvl2/3 derivations and follows the format in
    :ref:`SCION Address Header <scion-address-header>`.


DRKey uses AES-CBC MAC as PRF. The MAC is computed over the following fields:

* **type** (1 byte)
* **protocol** in Lvl2 generic-protocol derivations (2 bytes)
* **ISD-AS address** in Lvl1 derivations (8 bytes)
* **Host type/length** in Lvl2/3 derivations (4-bit, padded to 1 byte)
* **Host address** in Lvl2/3 derivations (variable size).

The derivation using CBC MAC is safe since all fields are of a fixed size,
except for the host address whose length is prepended.

Key Validity time
=================

Epochs
------
An epoch is an interval between a starting and ending point in time. The epoch
length can be chosen by a given AS and can change over time, however, epochs
must not overlap. Thus, a secret value is associated with exactly one epoch.

Every AS can define different epoch lengths for each protocol-specific
0th level key.

Defining a reasonable lower bound for the epoch length used in DRKey
is necessary to avoid nonsensical scenarios. This value is
globally set to 6 minutes.

.. note::

  This lower bound might be changed in the future in case a more suitable
  value is found.

Grace period
------------
We define a short overlapping period in which the protocol accepts packets with the key
for the previous epoch *i-1* and also for the current one *i*. This period should be
ideally as short as possible, although long enough to allow using the same key for
single packet request/response use cases (e.g. a few seconds). Thus, we set
``GRACE_PERIOD = 5 seconds``.

.. _drkey-prefetching:

Prefetching period
------------------
ASes will be allowed to prefetch keys some time before the key for the current epoch expires.
This period must be long enough to allow every remote AS to attempt the key prefetching
enough times to be succesful even in the presence of failures. However, this period
should not be too long, since the issuer AS is not assumed to carry out any changes
once it has issued keys for a given epoch (e.g. modifying SV epoch duration,
rotating the master secret, etc.).

We suggest globally setting  ``PREFETCHING_PERIOD = 30 minutes``.

.. note::

  Whether ASes are allowed to request/serve keys for past epochs is up for discussion.

Key establishment
=================

Level 1 key establishment
-------------------------

The Level 1 key establishment occurs between CSes located in different ASes.
The subject-AS on the slow side (i.e. the AS requesting the key) will establish a TLS secure connection with
the issuer-AS  on the fast side (i.e. the AS serving the key). Both parties identify each other by using
the CP-PKI infrastructure.

The Level 1 key request message contains the ``validTime`` for which the key must be active
and the ``protocol_id``. The Level 1 key response includes the symmetric key along with the epoch
for which this key will be valid.

The ``protocol_id`` is either set to ``GENERIC = 0`` to request Lvl1 keys that will be derived according to
the `generic-protocol` hierarchy or to the protocol number for the `protocol-specific` derivation.

Level 0/2/3 key establishment
-----------------------------

Even though Level 0/2/3 key exchange happens within the same AS (i.e. intra-AS communication),
the protocol should establish a secure channel.
This would avoid that hosts in the AS can eavesdrop on symmetric keys that are not
intended for them.

The CS will only respond to the specific request if the requesting host
is authorized to receive the requested key.
This is especially important in the Level 0 key case since only trustworthy nodes should
be authorized to receive this key.

The Level 0 key request contains the ``validTime`` and the specific ``protocol_id``.
The CS responds with the SV and the epoch for which this key will be valid.

The Level 2/3 key request includes the ``validTime`` and the necessary host and AS
information (depending on the key type).
The server responds with the symmetric key and the epoch.

The ``protocol_id`` in Lvl2/3 requests is always set to the final protocol identifier.
The key service will choose between the `protocol-specific` derivation, if it exists, or
the `generic-protocol` derivation, otherwise.

Spreading Level 1 key requests
==============================

Shared symmetric keys are short-lived to avoid explicit key revocation. In order
to avoid peaks in the requests for Level 1 keys derived from a given SV, every requesting
CS (i.e. the CS on the slow side) SHOULD wait a random time before trying to prefetch
the Level 1 key. This time ``t`` is u.r.d. in the interval [0, 15] minutes.

In this manner, the CS on the slow side SHOULD NOT request a Level 1 key before
``epoch_end - (PREFETCHING_PERIOD - t)`` instant in time (the ``PREFETCHING_PERIOD``
is defined in :ref:`drkey-prefetching`).

DRKey Messages Format
=====================

The DRKey messages format is specified in terms of their `protobuf
<https://developers.google.com/protocol-buffers>`__ definitions.

Protocol Enum
-------------

DRKeys are protocol-specific. The following enum defines the valid protocol IDs.

.. code-block:: protobuf

    enum Protocol {
      // Generic (unspecified protocol)
      GENERIC = 0;
      // SCION Control Message Protocol (SCMP)
      SCMP = 1;
      reserved 65536 to max; // only 16-bit values allowed
    }

Control Plane Messages
----------------------

Control plane messages are used to establish level 0 and level 1 keys. They are always between SCION
control plane entities, e.g., between two CSes in two different ASes (level 1) or between an CS and
a router within the same AS (level 0).

.. code-block:: protobuf

    // SVRequest is used to request a secret value (level 0 key) for a given
    // epoch and protocol. The secret value can then further be used to
    // locally derive higher-level keys.
    message SVRequest{
      // Point in time when the requested key is valid.
      Timestamp val_time = 1;
      // Protocol value.
      Protocol protocol_id = 2;
    }

    // SVResponse contains the secret value (level 0 key) and the epoch for which
    // it is valid.
    message SVResponse{
      // Begin of the SV validity period.
      Timestamp epoch_begin = 1;
      // End of the SV validity period.
      Timestamp epoch_end = 2;
      // SV key.
      bytes key = 3;
    }

    // Lvl1Request is used to request a level 1 key for a given epoch and protocol.
    message Lvl1Request{
      // Point in time when the requested key is valid.
      Timestamp val_time = 1;
      // Protocol value.
      Protocol protocol_id = 2;
    }

    // Lvl1Response contains the level 1 key and the epoch for which it is valid.
    message Lvl1Response{
      // Begin of validity period.
      Timestamp epoch_begin = 1;
      // End of validity period.
      Timestamp epoch_end = 2;
      // Lvl1 key.
      bytes key = 3;
    }

Application Level Messages
--------------------------

Application level messages are used by SCION applications or SCION daemons to request and establish
level 2 and level 3 keys from a CS in their AS. These messages constitute the API for applications
to use DRKeys.

.. code-block:: protobuf

    // HostASRequest is used to request a Host-AS (level 2) key for a given epoch and protocol.
    message HostASRequest{
      // Point in time where requested key is valid.
      Timestamp val_time = 1;
      // Protocol value.
      Protocol protocol_id = 2;
      // Src ISD-AS of the requested DRKey.
      uint64 src_ia = 3;
      // Dst ISD-AS of the requested DRKey.
      uint64 dst_ia = 4;
      // Src Host of the request DRKey.
      string src_host = 5;
    }

    // HostASResponse contains the Host-AS (level 2) key and the epoch for which it is valid.
    message HostASResponse{
      // Begin of validity period of DRKey.
      Timestamp epoch_begin = 1;
      // End of validity period of DRKey.
      Timestamp epoch_end = 2;
      // Lvl2 key.
      bytes key = 3;
    }

    // ASHostRequest is used to request an AS-Host (level 2) key for a given epoch and protocol.
    message ASHostRequest{
      // Point in time where requested key is valid.
      Timestamp val_time = 1;
      // Protocol value.
      Protocol protocol_id = 2;
      // Src ISD-AS of the requested DRKey.
      uint64 src_ia = 3;
      // Dst ISD-AS of the requested DRKey.
      uint64 dst_ia = 4;
      // Dst Host of the request DRKey.
      string dst_host = 5;
    }

    // ASHostResponse contains the AS-Host (level 2) key and the epoch for which it is valid.
    message ASHostResponse{
      // Begin of validity period of DRKey.
      Timestamp epoch_begin = 1;
      // End of validity period of DRKey.
      Timestamp epoch_end = 2;
      // Lvl2 key.
      bytes key = 3;
    }

    // HostHostRequest is used to request a Host-Host (level 3) key for a given epoch and protocol.
    message HostHostRequest{
      // Point in time where requested key is valid.
      Timestamp val_time = 1;
      // Protocol value.
      Protocol protocol_id = 2;
      // Src ISD-AS of the requested DRKey.
      uint64 src_ia = 3;
      // Dst ISD-AS of the requested DRKey.
      uint64 dst_ia = 4;
      // Src Host of the request DRKey.
      string src_host = 5;
      // Dst Host of the request DRKey.
      string dst_host = 6;
    }

    // HostHostResponse contains the Host-Host (level 3) key and the epoch for which it is valid.
    message HostHostResponse{
      // Begin of validity period of DRKey.
      Timestamp epoch_begin = 1;
      // End of validity period of DRKey.
      Timestamp epoch_end = 2;
      // Lvl2 key.
      bytes key = 3;
    }

.. _drkey-protocol-identifiers:

Assigned Protocol Identifiers
=============================

The following protocol identifiers are assigned:

======= ========== ============================================================== =============
Decimal Identifier Description                                                    Reference
======= ========== ============================================================== =============
0       Generic    Identifier for Level 1 key in :ref:`drkey-generic-derivation`  :ref:`drkey-generic-derivation`
1       SCMP       Authentication of SCMP messages                                :ref:`scmp-specification`
======= ========== ============================================================== =============
