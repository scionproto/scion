.. _scion_showpaths:

scion showpaths
---------------

Display paths to a SCION AS

Synopsis
~~~~~~~~


'showpaths' lists available paths between the local and the specified
SCION ASe a.

By default, the paths are probed. Paths served from the SCION Deamon's might not
forward traffic successfully (e.g. if a network link went down, or there is a black
hole on the path). To disable path probing, set the appropriate flag.

If no alive path is discovered, json output is not enabled, and probing is not
disabled, showpaths will exit with the code 1.
On other errors, showpaths will exit with code 2.

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

  scion showpaths [flags]

Examples
~~~~~~~~

::

    scion showpaths 1-ff00:0:110 --extended
    scion showpaths 1-ff00:0:110 --local 127.0.0.55 --json
    scion showpaths 1-ff00:0:111 --sequence="0-0#2 0*" # outgoing IfID=2
    scion showpaths 1-ff00:0:111 --sequence="0* 0-0#41" # incoming IfID=41 at dstIA
    scion showpaths 1-ff00:0:111 --sequence="0* 1-ff00:0:112 0*" # 1-ff00:0:112 on the path
    scion showpaths 1-ff00:0:110 --no-probe

Options
~~~~~~~

::

      --dispatcher string      Path to the dispatcher socket (default "/run/shm/dispatcher/default.sock")
      --epic                   Enable EPIC.
  -e, --extended               Show extended path meta data information
      --format string          Specify the output format (human|json|yaml) (default "human")
  -h, --help                   help for showpaths
      --isd-as isd-as          The local ISD-AS to use. (default 0-0)
  -l, --local ip               Local IP address to listen on. (default zero IP)
      --log.level string       Console logging level verbosity (debug|info|error)
  -m, --maxpaths int           Maximum number of paths that are displayed (default 10)
      --no-color               disable colored output
      --no-probe               Do not probe the paths and print the health status
  -r, --refresh                Set refresh flag for SCION Deamon path request
      --sciond string          SCION Deamon address. (default "127.0.0.1:30255")
      --sequence string        Space separated list of hop predicates
      --timeout duration       Timeout (default 5s)
      --tracing.agent string   Tracing agent address

SEE ALSO
~~~~~~~~

* `scion <scion.html>`_ 	 - A clean-slate Internet architecture

