# Hidden Paths

This file documents the design for the Hidden Paths infrastructure.

## Naming

| Name                                     | Explanation                                                     |
| ---------------------------------------- | --------------------------------------------------------------- |
| Hidden Path Group (HPG)                  | Group within which hidden path information is shared            |
| Hidden Path Group Configuration (HPGCfg) | Configuration defining a Hidden Path Group                      |
| Hidden Path Server (HPS)                 | Server caching hidden segments / answering hidden path requests |

## Overview

Hidden path communication enables the hiding of specific path segments, i.e. certain path segments
are only available for authorized ASes. In the common case, path segments are publicly available to
any network entity. They are fetched from path servers and used to construct forwarding paths. In a
Hidden Path communication setting, certain down-segments are not registered at the public path
servers. Instead, they are registered at dedicated Hidden path servers (HPS) which enforce access
control, such that only authorized entities can fetch and use these segments to create forwarding
paths. Likewise, the corresponding up-segment is registered as hidden up-segment at the local Path
Server such that endhosts are aware that they are using hidden path communication to leave the AS.

![Hidden Path Communication](fig/hidden_paths/HiddenPath.png)

*Hidden Path communication scheme:*

1. Group Owner creates a HPG and shares the configuration out-of-band
1. Writer ASes register down-segments at Registries of their group
1. Reader ASes query local HPS for hidden segments
1. Reader ASes can communicate with Writer ASes based on hidden path segments

## Design

### Hidden Path Group

A hidden path group is defined as a group of ASes within which hidden path
information is shared. A hidden path group consists of:

- GroupID: Unique 64bit identification of the group: OwnerAS<sub>48bit</sub>||GroupID<sub>16bit</sub>
- Version: A version indicating the version of the configuration
- Owner: AS ID of the owner of the hidden path group. The Owner AS is responsible for maintaining
  the hidden path group configuration and keeping the group's HPS up-to-date with the latest
  version *(Access: Read/Write)*
- Writers: All ASes in the group which are allowed to register hidden paths *(Access: Read/Write)*
- Readers: All ASes in the group which are allowed to read hidden path information *(Access: Read)*
- Registries: All ASes in the group at which writers register hidden paths

The HPGCfg is shared amongst the members of the group out-of-band. It
is the group owner's responsibility to disseminate updated versions to all
members. An online way to initially share and update the HPGCfg might be added in the future.

(See an example group configuration in the [Implementation](#Hidden-Path-Group-Configuration) section)

### Hidden Path Service

Each AS in the hidden path group runs a Hidden Path Server as a service. While at first it seems
that HPS and PS serve a similar purpose, a closer look justifies why HPS should run as a dedicated
service: The segment lookup on an HPS is simple compared to the lookup done by a PS since only
down-segments need to be returned. Not much of the PS logic could be re-used. Furthermore, an HPS
needs to perform ACL checks on requesters based on HPGCfgs. This logic is not needed by a regular
PS. Merging the two services would unnecessarily complicate both designs and harm the development of
future, more sophisticated accesss control mechanisms on HPS.

Each HPS serves two purposes:

- Caching Hidden Path segment information and serving this information to sciond and forwarding HPS
- Forwarding hidden path requests on behalf of sciond to `Registries` of the group

Hidden Path Servers are listed as
`HiddenPathService` in the topology file. The corresponding service address is
`SvcHPS`.

### Segment Registration

The Beacon Server needs to distinguish between segments to be registered at the Path Server and the
ones to be registered at the Hidden Path Server. Additionally, a segment can be registered as
up-segment only or as down-segment only. These decisions are based on a policy defined in the
Beacon Server's configuration file. The policy groups segments by public and hidden segments. For
each segment, identified by its interface ID, the following parameters can be defined:

- MaxExpiration:  The time interval after which the segment becomes invalid
- RegDown: Whether to register the segment as down-segment at the Core PS / HPS
- RegUp: Whether to register the segment as (hidden) up-segment at the local PS / HPS

Segments not explicitly listed are either fully registered as public up- and down-segments or not
registered at all, depending on the configured default action.

Note that a hidden segment registered as hidden and the same segment registered publicly need to be
distinguishable. This is achieved by adding an extension to the `ASEntry` of the final AS in the
segment.

The Beacon Server can be configured to not allow the registration of a segment both as public and hidden.

(See an example policy in the [Implementation](#Segment-Registration-Policy) section)

### Path Lookup

Additional to up-, core- and down-segments, sciond is responsible for fetching hidden down-segments.
sciond periodically queries the local HPS to fetch all HPGCfgs of which it is a member. Clients of
sciond have to explicitly ask sciond for hidden paths. Clients can include a specific `GroupID` in
their request; otherwise sciond checks all HPGCfgs and extracts the HPG `GroupID`s of all those
groups where the destination is a Writer (or Owner) of that group. With the obtained `GroupID`s and
the given destination, sciond then requests hidden down-segments from its local HPS. The local HPS
selects a Registry for each `GroupID`, partitioning the `GroupID`s into disjoint subsets based on
shared Registries. HPS then resolves the request by applying one of two cases for each subset:

1. The local HPS is a Registry of the groups in the subset, and thus resolves the request by
   querying its database
1. The local HPS is *not* a Registry of the groups in the subset. The request is
   resolved by querying the shared Registry of the given groups.

The HPS then replies to sciond with a map of `GroupID` -> (`SegReply`,
`error`).

![Path Lookup](fig/hidden_paths/PathLookup.png)

### Security

Various operations in this design are security critical and require client/server authentication:

1. For the creation of HPGs we assume that the chosen out-of-band mechanism is safe.
1. For registrations from BS to HPS we need to authenticate the HPS. Currently, there is no server
   authentication in SCION. This needs to be implemented for the segment registration to be secure.
1. sciond querying paths from the local HPS is secured by AS internal policies.
1. A local HPS fetching segments from a remote HPS is authenticated by signing the request with the
   local ASes signing key. The remote HPS can verify the signature using the client ASes public key.

## Implementation

### Hidden Path Group Configuration

Below is an example of a Hidden Path Group configuration file (`HPGCfg_ff00_0_110-69b5.json`):

```json
{
    "GroupID": "ff00:0:110-69b5",
    "Version": 1,
    "Owner": "1-ff00:0:110",
    "Writers": [
        "1-ff00:0:111",
        "1-ff00:0:112"
    ],
    "Readers": [
    "1-ff00:0:113",
    "1-ff00:0:114"
    ],
    "Registries": [
        "1-ff00:0:110",
        "1-ff00:0:111",
        "1-ff00:0:113"
    ]
}
```

### Segment Registration Policy

Below is an example `hp_policy.yml` configuration. In `HPGroups` all the HPGs available to the
beacon service are listed. Furthermore, the configuration contains the segment registration policies
in the `SegmentRegistration` section. The file `hp_policy.yml` in turn is pointed to by the
`bs.toml` file by specifying the `HiddenPathRegistration` parameter.

```yaml
---
HPGroups:
  "ff00:0:110-69b5":
    CfgFilePath: testdata/HPGCfg_ff00_0_110-69b5.json
  "ffaa:0:222-abcd":
    CfgFilePath: testdata/HPGCfg_ffaa_0_222-abcd.json
SegmentRegistration:
  DefaultAction: register
  HiddenAndPublic: true
  Policies:
    2:
      PS:
        RegUp: true
        RegDown: true
        MaxExpiration: 1h
      HPS:
        "ff00:0:110-69b5":
          RegUp: true
          RegDown: true
          MaxExpiration: 1h
        "ffaa:0:222-abcd":
          RegUp: true
          RegDown: true
          MaxExpiration: 1h
    3:
      PS:
        RegUp: true
        RegDown: true
        MaxExpiration: 1h
```

The default action is set to `register`, this means that all segments not listed in this
configuration are registered as up- and down-segment with default expiration.
Note that the segment with IFID 2 is both registered as hidden and public. This is allowed by
setting `HiddenAndPublic`.

### Message Definitions

(TBD)

### Hidden Path Server

#### General Structure

The HPS is structured similar to existing go infra services. It uses:

- go/lib/env (for configuration and setting up the service)
- go/lib/infra (for sending messages)
- go/lib/pathdb (for storing hidden segments)

#### Handlers

The HPS has the following handlers:

- `HPSegRegHandler`: Handler accepting a `GroupID` and a list of segments to be registered as hidden
  down-segments for that group *(Access: Owner/Writers)*
- `HPSegReqHandler`: Accepting a list of `GroupID`s, responding with hidden down-segments
  corresponding to those groups *(Access: Owner/Readers)*
- `HPGCfgReqHandler`: Returns a list of all `HPGCfg`s the requester is a Reader of *(Access: Owner/Writers/Readers)*
