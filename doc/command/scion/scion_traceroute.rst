:orphan:

.. _scion_traceroute:

scion traceroute
----------------

Trace the SCION route to a remote SCION AS using SCMP traceroute packets

Synopsis
~~~~~~~~


'traceroute' traces the SCION path to a remote AS using
SCMP traceroute packets.

If any packet is dropped, traceroute will exit with code 1.
On other errors, traceroute will exit with code 2.
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

  scion traceroute [flags] <remote>

Examples
~~~~~~~~

::

    scion traceroute 1-ff00:0:110,10.0.0.1

Options
~~~~~~~

::

      --epic                   Enable EPIC.
      --format string          Specify the output format (human|json|yaml) (default "human")
  -h, --help                   help for traceroute
  -i, --interactive            interactive mode
      --isd-as isd-as          The local ISD-AS to use. (default 0-0)
  -l, --local ip               Local IP address to listen on. (default invalid IP)
      --log.level string       Console logging level verbosity (debug|info|error)
      --no-color               disable colored output
      --refresh                set refresh flag for path request
      --sciond string          SCION Daemon address. (default "127.0.0.1:30255")
      --sequence string        Space separated list of hop predicates
      --timeout duration       timeout per packet (default 1s)
      --tracing.agent string   Tracing agent address

SEE ALSO
~~~~~~~~

* :ref:`scion <scion>` 	 - SCION networking utilities.

