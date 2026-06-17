.. _path-type-hummingbird:

Path Type: Hummingbird
======================
The path type Hummingbird has the following layout::

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          PathMetaHdr                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           InfoField                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              ...                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           InfoField                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  HopField or FlyoverHopField                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  HopField or FlyoverHopField                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              ...                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+`

It consists of a path meta header, up to 3 info fields and up to 52 :superscript:`1` hop fields or
flyover hop fields.

The inclusion of a HopField or a FlyoverHopField is determined by the first bits of that field itself.
See HopField and FlyoverHopField below for more information.
A FlyoverHopField denotes a reserved (guaranteed forwarding) hop field,
while the presence or a regular HopField indicates best-effort forwarding as specified
by the SCION path type.

:superscript:`1` There is a maximum of 52 flyovers possible on any given path,
which comes from the encoding of the CurrHF.
See CurrHF in the Metaheader below for details.

..
    Comment:
    CurrHF (8 bits) and SegLen[3] (:math:`3 \times 7`bit) limit the amount of flyovers.
    A flyover is 5 lines (:math:`5 \times 4 = 20` bytes).
    CurrHF thus can offset up to :math:`2^8/5 = 51` (52 flyovers). Each SegLen is 7 bit,
    can represent up to :math:`2^7 / 5 = 25` flyovers each, :math:`3 \times 25 = 75`.
    The minimum between both CurrHF and SegLen is 52. I will fix this.


PathMetaHdr
-----------
The PathMetaHdr field is different from that of the SCION path type.
It is a 12 byte header containing meta information about the
Hummingbird path present in the path header. It has the following format::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | C |    CurrHF     |r|   Seg0Len   |   Seg1Len   |   Seg2Len   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          BaseTimeStamp                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  MillisTimestamp  |                  Counter                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

(C)urrINF
    2-bit index (0-based) pointing to the current info field (see offset calculations below).
CurrHF
    8-bit index (0-based) pointing to the start of the current hop field
    (see offset calculations below) in 4-byte increments.
    This index is increased by 3 for normal hop fields and by 5 for flyover hop fields,
    which are 12 B and 20 B long, respectively.
    This field can represent :math:`1 + (2^8 / 5) = 52` flyovers,
    or :math:`1 + (2^8 / 3) = 86` hop fields (without reservations).
r
    Unused and reserved for future use.
Seg{0,1,2}Len
    7-bit encoding of the length of each segment.
    The value in these fields is the length of the respective segment in bytes divided by 4.
    Seg[i]Len > 0 implies the existence of info field i.
    If a given Seg[i]Len is zero, all subsequent Seg[j]Len with j > i will also be zero.
    Each Seg[i]Len field can represent :math:`2^7/5 = 25` flyovers,
    or :math:`2^7 / 3 = 42` hop fields (without reservations).
BaseTimestamp
    A unix timestamp (unsigned integer, 1-second granularity, similar to beacon timestamp in
    normal SCION path segments) that is used as a base to calculate start times for
    flyovers and the high granularity MillisTimestamp.
MillisTimestamp
    Millisecond granularity timestamp, as offset from BaseTimestamp.
    Used to compute MACs for flyover hops and to check recentness of a packet.
Counter
    A counter for each packet that is sent by the source to ensure that the tuple (BaseTimestamp,
    MillisTimestamp, Counter) is unique. This can then be used for the optional duplicate suppression at an AS.


Path Offset Calculations
^^^^^^^^^^^^^^^^^^^^^^^^

Similarly to the SCION path type, the number of info fields present in the path is calculated
as the amount of Seg[i]Len that are greater than zero, based on the following:

.. code-block::

    function InfFieldCount(){
        if Seg2Len != 0:
            return 3
        else if Seg1Len != 0:
            return 2
        else if Seg0Len != 0:
            return 1
        else
            // All fields are zero. Intra-AS path.
            return 0
    }
    PresentInfoFieldCount = InfFieldCount()

The path offsets in bytes are computed as:

- :math:`InfoFieldOffset = 12 + 8 \times CurrINF`
- :math:`HopFieldOffset = 12 + 8 \times NumINF + 4 \times CurrHF`


InfoField
---------
The InfoField does not change with respect to the SCION path type one.
All fields retain the same size and the same semantics.

.. code-block::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |r r r r r r P C|     RSV       |            SegID              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          TimeStamp                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

r
    Unused and reserved for future use.
P
    Peering flag. If set to true, then the forwarding path is built as a peering path, which requires special  processing on the data plane.
C
    Construction direction flag. If set to true then the hop fields are arranged in the direction
    they have been constructed during beaconing.
RSV
    Unused and reserved for future use.
SegID
    Updatable field used in the MAC-chaining mechanism.
Timestamp
    Timestamp created by the initiator of the corresponding beacon.
    The timestamp is expressed in Unix time, and is encoded as an unsigned integer
    within 4 bytes with 1-second time granularity.
    It enables validation of the hop field by verification of the expiration time and MAC.


Regular HopField
----------------
This field type remains the same as the HopField in the SCION path type.
See

.. code-block::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |F r r r r r I E|   ExpTime     |         ConsIngress           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          ConsEgress           |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                        HopFieldMAC                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

F
    Flyover bit. Indicates whether this is a hop field or a flyover hop field. Set to 0 for HopFields.
r
    Unused and reserved for future use.
I
    ConsIngress Router Alert. If the ConsIngress Router Alert is set, the ingress router (in construction direction) will process the L4 payload in the packet.
E
    ConsEgress Router Alert. If the ConsEgress Router Alert is set, the egress router (in construction direction) will process the L4 payload in the packet.
ExpTime
    Expiry time of a hop field. The field is 1-byte long, thus there are 256 different values available to express an expiration time. The expiration time expressed by the value of this field is relative, and an absolute expiration time in seconds is computed in combination with the timestamp field (from the corresponding info field).
ConsIngress, ConsEgress
    The 16-bit interface IDs in construction direction.
HopFieldMAC
    6-byte MAC to authenticate the hop field. For details on how this MAC is calculated refer to the hop-field MAC computation of the SCION path type.


FlyoverHopField
---------------
A FlyoverHopField represents a guaranteed forwarding hop.

.. code-block::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |F r r r r r I E|   ExpTime     |         ConsIngress           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          ConsEgress           |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                           AggMAC                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  ResID                    |        BW         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        ResStartOffset         |         ResDuration           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

F Flyover bit
    Indicates whether this is a hop field or a flyover hop field. Set to 1 for FlyoverHopFields.
r, I, E, ExpTime, ConsIngress, ConsEgress
    These values are the same as in the standard HopField. Note that ExpTime is the expiration time of the standard HopField, not the expiration time of the reservation.
AggMAC
    The aggregate MAC (i.e., XOR) of the standard HopField MAC and the per-packet flyover MAC as per:

    .. math::
        \begin{align}
        AggMAC &= HopFieldMAC ~\oplus~ FlyoverMAC \\
        FlyoverMAC &= PRF+{Ak}(DstAddr || PktLen || TS) [: 6] \\
        TS &= ResStartOffset || MillisTimestamp || Counter \\
        DstAddr &= DstISD || DstAS \\
        PktLen &= PayloadLen + 4 \times HdrLen \\
        \end{align}

    See `Authentication Key (A_k) Computation`_ and `FlyoverMAC Computation`_ for more details.
ResID
    22-bit Reservation ID, this allows for approximately 4 million concurrent reservations for a given ingress/egress pair.
BW
    10-bit bandwidth field indicating the reserved bandwidth which allows for 1024 different values. The values could be encoded similarly to floating point numbers (but without negative numbers or fractions), where some bits encode the exponent and some the significant digits. For example, one can use 5 bits for the exponent and 5 bits for the significand and calculate the value as significand if exponent = 0 or (32 + significand) << (exponent - 1) otherwise. This allows values from 0 to almost :math:`2^{36}` with an even spacing for each interval between powers of 2.
ResStartOffset
    The offset between the BaseTimestamp in the Path Meta header and the start of the reservation (in seconds). This allows values up to approximately 18 hours in second granularity.
ResDuration
    Duration of the reservation, i.e., the difference between the timestamps of the start and expiration time of the reservation.


Authentication Key (:math:`A_k`) Computation
--------------------------------------------
The first step to compute the flyover MAC is to obtain the authentication key :math:`A_k`.
This is done by creating a 16-byte input buffer (block) and  encrypting it with AES-128,
initialized with the Hummingbird secret value (analogous to the regular SCION master secret).
This input buffer is created as follows:

.. code::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         ConsIngress           |          ConsEgress           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   ResID                   |        BW         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            ResStart                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         ResDuration           |          0 Padding            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

One block of AES derives the authentication key. Example in Go:

.. code::

    inputBuff := prepareBuffer(in, eg, resID, bw, restStart, resDuration)
    block, _ = aes.NewCipher(secretValue)
    block.Encrypt(inputBuff, inputBuff)
    authenticationKey := inputBuff


FlyoverMAC Computation
----------------------
Analogous to the authentication key computation, the flyover MAC computation
is done by a block encryption with AES-128,
initialized with the authentication key :math:`A_k`, on a 16-byte input buffer.
The input buffer layout is depicted below:

.. code::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            DstISD             |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                            DstAS                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            PktLen             |        ResStartOffset         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  MillisTimestamp  |                  Counter                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Then the FlyoverMAC is computed with one block of AES. Example in Go:

.. code::

    inputBuff := prepareBuffer(dstISD, dstAS, pktLen, restStartOffset, millisTimestamp, counter)
    block, _ = aes.NewCipher(authenticationKey)
    block.Encrypt(inputBuff, inputBuff)
    flyoverMAC := inputBuff
