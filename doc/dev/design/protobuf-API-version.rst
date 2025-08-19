********************
Protobuf API Version
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

There are multiple ways to approach this. Some ways require the control service to
provide a Version Service and Version Information.

Version Service and Version Information
---------------------------------------

The control service offer a dedicated Version Service:

.. code-block:: protobuf

  service VersionService {
    // Return version information about the service API.
    rpc Version(VersionRequest) returns (VersionResponse) {}
  }

  message VersionRequest {}

  message VersionResponse {
    // API version
    required uint32 api_version = 1;
    // Map of individual components and their versions,
    map<string, uint32> component_versions = 2;
    map<string, VersionRange> component_versions = 2;
  }

  message VersionRange {
    // The minimum and maximum version of a service that is supported by the server.
    required int32 min = 1;
    required int32 max = 2;
  }

The `api_version` is an integer that is incremented whenever any of the
APIs of any component changes.

The `component_version` is a map `<component name> -> <component API version>`.
The component API version is incrmented whenever the component's API changes
in a way that is **not** backwards compatible.
Examples of component names are: `segments`, `drkey`, `cppki`, `renewal`

The component versions are only provided for convenience. They indicate to
a client which version of a component needs to be instantiated.
If this information would not be provided, it would have to be hardcoded
in the client.

Examples:

- Changes that are backwards compatible, such as adding a request or service
  to an api requires only an increment of the `api_version`.
- Removing a request or service requires incrementing the `api_version` and
  the `component_version`. To maintain backward compatibility, this would
  probably also result in a new `.proto` file.

TBD:

- Do we need the component versions?
- Should we provide a list VersionResponses, representing all versions that
  a server supports?
- We could simply replace all component version numbers with list of supported
  version numbers.
  The client can then just use the latest version of a ProtoService that is
  available both locally and on the server.
  A version range is not really required for the API version.


Three different ways to approach this
-------------------------------------

1) Separate Version Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The control service should offer a service API to request version information.
The API should provide an integer version identifier and, **possibly**,
individual version identifiers for each service.
The request should **probably** be available through its own service.

For example:

Advantages:

- Cleanest solution
- Best error messages (client support version X, server requires version Y).

Disadvantages:

- Extra roundtrip

2) Optimistic Usage
^^^^^^^^^^^^^^^^^^^

In this approach, a client optimistically uses the latest version that it supports.
If that fails, it uses the Version Service service to find out which versions
are supported and selects one of these version or reports an error.

Advantages:

- No extra roundtrip (best case / expected normal case)
- Likely succeeds

Disadvantages

- Two extra roundtrip if initial attempt fails: request version + use compatible API
- Uses error handling in normal code path

3) Brute Force
^^^^^^^^^^^^^^

Start with the highest known version and iterate through all version until one works.

Advantages:

- No extra roundtrip (best case / expected normal case)
- No extra Version Service or Version Info required

Disadvantages:

- Theoretically many roundtrips required until a compatible version is found
- Uses error handling in normal code path


Rationale
=========
[A discussion of alternate approaches and the trade-offs, advantages, and disadvantages of the specified approach.]


Compatibility
=============

There are no breaking changes.

If the client does not support API versions, then the feature will not
be used.

If the server does not support API versions, then the version request will
fail and the client should assume version `1`.


Implementation
==============

- Add version information to control server implementations
- Add version information to client libraries

- Document clearly (in each proto file?) that any change should result
  in incrmeneting the API version.
