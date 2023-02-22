:orphan:

.. _scion_ping:

scion ping
----------

Test connectivity to a remote SCION host using SCMP echo packets

Synopsis
~~~~~~~~


'ping' test connectivity to a remote SCION host using SCMP echo packets.

When the \--count option is set, ping sends the specified number of SCMP echo packets
and reports back the statistics.

When the \--healthy-only option is set, ping first determines healthy paths through probing and
chooses amongst them.

If no reply packet is received at all, ping will exit with code 1.
On other errors, ping will exit with code 2.

The paths can be filtered according to a sequence. A sequence is a string of
space separated HopPredicates. A Hop Predicate (HP) is of the form
'ISD-AS#IF,IF'. The first IF means the inbound interface (the interface where
packet enters the AS) and the second IF means the outbound interface (the
interface where packet leaves the AS).  0 can be used as a wildcard for ISD, AS
and both IF elements independently.

HopPredicate Examples:

======================================== ==================
 Match any:                               0
 Match ISD 1:                             1
 Match AS 1-ff00:0:133:                   1-ff00:0:133
 Match IF 2 of AS 1-ff00:0:133:           1-ff00:0:133#2
 Match inbound IF 2 of AS 1-ff00:0:133:   1-ff00:0:133#2,0
 Match outbound IF 2 of AS 1-ff00:0:133:  1-ff00:0:133#0,2
======================================== ==================

Sequence Examples:

========== ====================================================
 sequence: "1-ff00:0:133#0 1-ff00:0:120#2,1 0 0 1-ff00:0:110#0"
========== ====================================================

The above example specifies a path from any interface in AS 1-ff00:0:133 to
two subsequent interfaces in AS 1-ff00:0:120 (entering on interface 2 and
exiting on interface 1), then there are two wildcards that each match any AS.
The path must end with any interface in AS 1-ff00:0:110.

========== ====================================================
 sequence: "1-ff00:0:133#1 1+ 2-ff00:0:1? 2-ff00:0:233#1"
========== ====================================================

The above example includes operators and specifies a path from interface
1-ff00:0:133#1 through multiple ASes in ISD 1, that may (but does not need to)
traverse AS 2-ff00:0:1 and then reaches its destination on 2-ff00:0:233#1.

Available operators:

====== ====================================================================
  ?     (the preceding HopPredicate may appear at most once)
  \+    (the preceding ISD-level HopPredicate must appear at least once)
  \*    (the preceding ISD-level HopPredicate may appear zero or more times)
  \|    (logical OR)
====== ====================================================================


::

  scion ping [flags] <remote>

Examples
~~~~~~~~

::

    scion ping 1-ff00:0:110,10.0.0.1
    scion ping 1-ff00:0:110,10.0.0.1 -c 5

Options
~~~~~~~

::

  -c, --count uint16           total number of packets to send
      --dispatcher string      Path to the dispatcher socket (default "/run/shm/dispatcher/default.sock")
      --epic                   Enable EPIC for path probing.
      --format string          Specify the output format (human|json|yaml) (default "human")
      --healthy-only           only use healthy paths
  -h, --help                   help for ping
  -i, --interactive            interactive mode
      --interval duration      time between packets (default 1s)
      --isd-as isd-as          The local ISD-AS to use. (default 0-0)
  -l, --local ip               Local IP address to listen on. (default zero IP)
      --log.level string       Console logging level verbosity (debug|info|error)
      --max-mtu                choose the payload size such that the sent SCION packet including the SCION Header,
                               SCMP echo header and payload are equal to the MTU of the path. This flag overrides the
                               'payload_size' and 'packet_size' flags.
      --no-color               disable colored output
      --packet-size uint       number of bytes to be sent including the SCION Header and SCMP echo header,
                               the desired size must provide enough space for the required headers. This flag
                               overrides the 'payload_size' flag.
  -s, --payload-size uint      number of bytes to be sent in addition to the SCION Header and SCMP echo header;
                               the total size of the packet is still variable size due to the variable size of
                               the SCION path.
      --refresh                set refresh flag for path request
      --sciond string          SCION Deamon address. (default "127.0.0.1:30255")
      --sequence string        Space separated list of hop predicates
      --timeout duration       timeout per packet (default 1s)
      --tracing.agent string   Tracing agent address

SEE ALSO
~~~~~~~~

* :ref:`scion <scion>` 	 - SCION networking utilities.

