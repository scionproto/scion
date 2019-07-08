# Hidden Paths

This file documents the design for the Hidden Paths infrastructure.

- Author: Claude Hähni
- Last updated: 2019-07-08
- Status: draft

## Naming

| Name                     | Explanation                                                     |
| ------------------------ | --------------------------------------------------------------- |
| Hidden Path Group (HPG)  | Group within which hidden path information is shared            |
| Hidden Path Server (HPS) | Server caching hidden segments / answering hidden path requests |

## Overview

Hidden Path communication enables entities to obtain and use specific path segments to build AS level end-to-end paths. In the common case, path segments are publicly available to any network entity. They are fetched from path servers and used to construct forwarding paths. In a Hidden Path communication setting, certain down-segments are not registered at the public path servers. Instead, they are reigistered at a dedicated Hidden path server (HPS) which enforces access control, such that only authorized entities can fetch and use these segments to create forwarding paths.

![Hidden Path Communication](fig/hidden_paths/HiddenPath.png)  
*Hidden Path communication scheme:*  
*1: Group Owner creates a HPG and shares the configuration out-of-band*  
*2: Writer ASes register down-segments at Registries of their group*  
*3: Reader ASes query local HPS for hidden segments*  
*4: Reader ASes can communicate with Writer ASes based on hidden path segments*

## Design

### Hidden Path Group

A hidden path group is defined as a group of ASes within which hidden path information is shared. A hidden path group consists of:
- GroupID: Unique 64bit identification of the group: OwnerAS<48bit>||GroupID<16bit>
- Version: A version indicating the version of the configuration
- Owner: AS ID of the owner of the hidden path group. Responsible for maintaining the hidden path group configuration and keeping the group's HPS up-to-date with the latest version, Access: Read/Write
- Writers: All ASes in the group which are allowed to register hidden paths, Access: Read/Write
- Readers: All ASes in the group which are allowed to read hidden path information, Access: Read
- Registries: All ASes in the group at which writers register hidden paths

The HPG configuration is shared amongst the members of the group out-of-band. It is the group owner's responsibility to disseminate updated versions to all members.

(See an example group configuration in the *Implementation* section)

### Hidden Path Service

Each AS in the hidden path group runs a Hidden Path Server as a service. `Registries` contain the Hidden Path segment information, other HPS merely act as forwarders to fetch this information. Hidden Path Servers are listed as `HiddenPathService` in the topology file. The corresponding service address is `SvcHPS`.

### Segment Registration

The Beacon Server needs to distinguish between segments to be registered at the Path Server and the ones to be registered at the Hidden Path Server.
This decision is based on a policy defined in the Beacon Server's configuration file. The policy is a list of segments defined as follows:
- Interface: The id of the interface the segment ends in
- TTL:  The time interval after which the segment becomes invalid
- Remote register mode: Whether the segment is hidden from remote Path Servers (not usable as down-segment for non-authorized ASes)
- Local register mode: Whether the segment is hidden from the local Path Server (not usable as up-segment)

(See an example policy in the *Implementation* section)

### Path Lookup

Additional to up-, core- and down-segments, SCION daemon is responsible for fetching hidden down-segments. SCION daemon uses the HPG configuration to detect whether it has to do a hidden path lookup. For a given request, it checks all HPGs and extracts the HPG `GroupID` of all those groups where the destination is a Writer (or Owner) of that group. With these `GroupID`s and the given destination, SCION daemon then requests hidden down-segments from its local HPS. The local HPS selects a Registry for each `GroupID`, partitioning the `GroupID`s into disjoint subsets based on shared Registries. HPS then resolves the request by applying one of two cases for each subset:
1. The local HPS is a Registry of the groups in the subset, and thus resolves the request by querying its database
2. The local HPS is *not* a Registry of the groups in the subset. The request is resolved by querying the shared Registry of the given groups.

The HPS then replies to SCION daemon with a map of `GroupID` -> (`SegReply`, `error`).

![Path Lookup](fig/hidden_paths/PathLookup.png)

## Implementation

### Hidden Path Group

Below is an example of a Hidden Path Group configuration file (`HpCfg_281474977720757.json`):

```json
{
	"GroupID": 281474977720757,
	"Version": 1,
	"Owner": 4294967296,
	"Writers": [
		4564967297,
		5945949298
	],
	"Readers": [
		4644967299,
		4587496300
	],
	"Registries": [
		6544967301,
		5523887302,
		8454547303
	]
}
```

### Segment Registration

Below is an excerpt of an example `bs.toml` configuration. A new `hpGroups` section is added, with subsections for every HPG the AS is a member of. These subsections contain the path to the corresponding HPG configuration file and a list of segments which it registeres at the HPS.

```toml
[general]
ConfigDir = "gen/ISD1/ASff00_0_111/bs1-ff00_0_111-1"
ReconnectToDispatcher = true
ID = "bs1-ff00_0_111-1"

...

[hpGroups]
[hpGroups.281474977720757]
CfgFilePath = "path/to/HpCfg_281474977720757.json"

[[hpGroups.281474977720757.segments]]
interface = 5
TTL = 10
remoteHidden = true
localHidden = false

[[hpGroups.281474977720757.segments]]
interface = 8
TTL = 15
remoteHidden = true
localHidden = true 

[hpGroups.xxxxx]

...

[hpGroups.yyyyy]
    
...   

...
```

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
- `HPSegRegHandler`: Handler accepting a `GroupID` and a list of segments to be registered as hidden down-segments for that group  
Access: Owner/Writers
- `HPSegReqHandler`: Accepting a list of `GroupID`s, responding with hidden down-segments corresponding to those groups  
Access: Owner/Readers