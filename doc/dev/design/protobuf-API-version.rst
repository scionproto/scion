********************
ProtoBuf API Version
********************

- Author(s): T. Zäschke
- Last updated: 2025-08-18
- Discussion at: :issue:`NNNN`
- Status: **WIP**

Abstract
========
The Protobuf API has currently no version aidentifier that allows a client to
find out which API version a server supports.

Background
==========
The Protobuf API (segment requests, etc.) may change over time. Transitioning
between version would be easier, and error messages can be better, if a client
could find out what version a server supports.
Currently, the client can only try to use a given service and somehow handle
the error when the request fails.

Proposal
========
The control service should offer a service API to request version information.
The API should provide an integer version identifier and, **possibly**,
individual version identifiers for each service.
The request should **probably** be available through its own service.

For example:




Rationale
=========
[A discussion of alternate approaches and the trade-offs, advantages, and disadvantages of the specified approach.]

Compatibility
=============
[A discussion of breaking changes and how this change can be deployed.]

Implementation
==============
[A description of the steps in the implementation, which components need to be changed and in which order.]
