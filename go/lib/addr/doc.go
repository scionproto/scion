/*
Package addr contains types for SCION addressing.

A SCION address is composed of the following parts: ISD (ISolation Domain
identifier), AS (Autonomous System idenifier), and Host (the host address).

The allocations and formatting of ISDs and ASes are documented here:
https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering. Note that the
':' separator for AS formatting is not used in paths/filenames for
compatibility reasons, so '_' is used instead in those contexts.
*/
package addr
