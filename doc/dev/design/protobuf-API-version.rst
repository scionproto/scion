********************
Protobuf API Version
********************

- Author(s): T. Zäschke
- Last updated: 2025-09-02
- Discussion at: :issue:`NNNN`
- Status: **WIP**

Abstract
========
The Protobuf API has currently no version identifier that allows a client to
find out which API version a server supports.

Background
==========
The Protobuf API (segment requests, etc.) may change over time.
There are three types of changes:

1. Additional fields in messages. This is handled by protobufs backward
   compatibility. If a client tries to read a non-existing field, it will get `null`.
   If a server sends a field that the client doesn't know about, the client will ignore it.
2. Additional services. For a client to find out whether a `service` exists,
   they have to try it out and handle the error.
3. Removed or changed `messages` or `services`. It is recommended to use
   `v1`, `v2`, ... in the proto package name. However, this again requires
   trial and error handling.

The trial and error handling is especially problematic if we get multiple versions
and a client has to try out a whole range of versions before finding one (or not)
that works. This may require multiple network roundtrips, and error handling
as part of the default code path.

Examples of potential upcoming changes:

- A new `service` that returns path segments, but also accepts a filter/policy for segments
- A new `service` that allows streaming/paging of segments
- A new `service` that returns topology information (border routers etc)
- A new `service` for the private/anonymous ISD proposal

If a client could find out what version a server supports, transitioning between
version would be easier, and error messages could be better.
Currently, the client can only try to use a given service and somehow handle
the error when the request fails.

Proposal
========

Three different ways to approach this
-------------------------------------

The current preference is to go with option 2).

1) Separate Version Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The control service offers a service API to request version information.
The service returns an integer version identifier and, **possibly**,
individual version identifiers for each service.
The request should **probably** be available through its own service.

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

- Theoretically many roundtrips required until a compatible version is found.
  A client could use some kind of binary search to optimize this.
- Uses error handling in normal code path


Version Service and Version Information
---------------------------------------

Option 1) and 2) require the control service to offer a dedicated Version Service:

.. code-block:: protobuf

package proto.version;

service VersionService {
    // Return version information about the service API.
    rpc Version(VersionRequest) returns (VersionResponse) {}
  }

  message VersionRequest {}

  message VersionResponse {
    // API version
    uint32 api_version = 1;
    // Oldest API version supported by the server
    uint32 api_version_minimum = 2;
    // Software version
    string software_version = 3;
  }

The `api_version` is an integer that is incremented whenever any of the
APIs of any component changes.
The `api_version_minimum` is an integer that is incremented whenever any
old API is removed.
The `software_version` is a character string that describes the software
version, e.g., "scionproto 0.16".

The `VersionService` would be located in a separate package `proto.version`.

Examples:

- Changes that are backwards compatible, such as adding a request or service
  to an API requires only an increment of the `api_version`.
- Removing a request or service requires incrementing the `api_version_minimum`.
  To maintain backward compatibility, this would probably also result in a
  new `.proto` file.
- The version could also be used to indicate non-grpc features, such as NAT support.


Rationale
=========

Component Versioning
--------------------
Removing the component versioning is definitely possible. However, the component
versioning may help to implement versioning in clients. It may also
serve as a component registry, e.g., indicating to the client whether `drkey`
is supported or not.

.. code-block:: protobuf

  service VersionService {
    // Return version information about the service API.
    rpc Version(VersionRequest) returns (VersionResponse) {}
  }

  message VersionRequest {}

  message VersionResponse {
    // API version
    uint32 api_version = 1;
    // Oldest API version supported by the server
    uint32 api_version_minimum = 2;
    // Map of individual components and their versions,
    map<string, VersionRange> component_versions = 3;
  }

  message VersionRange {
    // The minimum and maximum version of a service that is supported by the server.
    required int32 max = 1;
    required int32 min = 2;
  }

The `component_version` is a map `<component name> -> <component API version>`.
The component API version is incremented whenever the component's API changes
in a way that is **not** backwards compatible.
Examples of component names are: `version`, `segments`, `drkey`, `cppki`, `renewal`

The component versions are only provided for convenience. They indicate to
a client which version of a component needs to be instantiated.
If this information would not be provided, it would have to be hardcoded
in the client.

Component versioning could also be used to advertise features such as
hidden segments or even NAT (not a protobuf API).


Semantic Versioning
-------------------
We could use semantic versioning for the API, e.g., major for breaking changes
and minor for changes that are backwards compatible. However, while this
complicates the API, it is not obvious how that would simplify implementations.
Even for backward compatible changes, the field/service is either available or
not.

Compatibility
=============

There are no breaking changes.

If the client does not support API versions, then the feature will not
be used.

If the server does not support API versions, then the version request will
fail and the client should assume version `0`.


Implementation
==============

- Add version information to control server implementations.
- Add version information to client libraries..

- Document clearly (in each proto file?) that any change should result
  in incrementing the API version.
