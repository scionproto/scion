# Embedding Static Information in SCION Beacons

In order to estimate certain properties of a SCION path segment, static
information about that path can be embedded inside the path construction beacons
in the form of an extension. The following document will explore ways to embed
static information into SCION PCBs. It will first give a definition of what is
considered to be "static information" in this context, before exploring 7
particular static properties, how to define them and how to implement them as
part of the SCION infrastructure.

## Static Properties

For the purpose of this document, we will adhere to the following definition of
a static property:

>A static property is any quantifiable piece of information describing a
>property of a SCION path segment that remains unchanged over the entire
>duration of the lifetime of that path segment.

Before proceeding, it shall be explicitly stated here that for the purpose of
this work, the following assumptions are made:

- SCION has reliable information about its own infrastructure
- SCION has access to a blackbox (which could be the AS itself, a dedicated
  SCION service or any other entity), which provides information that
  characterizes the AS topology and the routing processes within the AS
- The AS topology remains stable throughout the lifetime of a path segment

For the purpose of embedding static information in the SCION beacons, the
extension field in the AS Entry of the PCB will be used. Every extension field
starts with its type encoded in 1 byte. After that comes the payload, i.e. the
actual contents of the extension. In order to keep things simple while at the
same time retaining as much versatility as possible, we will introduce the new
extension-type "Static Property". Inside the payload of a Static Property
extension a special "subtype" field will be used, which denotes which property
in particular is encoded in the rest of the payload. We will now discuss the
structure of the payload for each type of property.

### Latency Information

#### Definition Latency

Latency Information is defined as follows:

> Latency Information refers to the total propagation delay on an end to end
> path, comprised of intra- and inter-AS delays and measured on the scale of
> milliseconds.

#### Use Cases Latency

- Allows to augment path selection policy in order to obtain low latency paths
- Shortening the duration it takes to fetch data and thus decreasing wait times
  for the user
- Time critical applications

#### Conceptual Implementation Latency

The latency information will be comprised of 2 parts:

- The subtype field, which identifies it
- A variable number of latency clusters A latency cluster serves to pool all
  interfaces which are attached to an intra-AS link (i.e. going "inside the AS)
  and have the same propagation delay (within a +-0.5 ms range) between them and
  the egress interface.

Each latency cluster is itself comprised of 3 types of elements:

- The intra-AS propagation delay for every interface in the cluster, in ms (1
  value per cluster)
- The interface ID for every interface in the class (1 value per interface)
- The inter-AS propagation delay for the connection attached to the interface,
  in ms

Information about the inter-AS latency, as well as the intra-AS latency between
the egress interface and every other interface is required to deal with
shortcut/peering paths (see diagram).

[diagram goes here]

### Geographic Information

#### Definition Geographic Information

Geographic Information is defined as follows:

> Geographic Information is the full set of GPS coordinates identifying the
> location of every SCION border router deployed by an AS, as well as a real
> life address associated with the location of each such SCION border router.

#### Use Cases Geographic Information

- Can be used to augment path selection policies in order to ensure paths do not
  leave a particular area, or alternatively ascertain that they never cross
  territory that is considered "undesirable" by the user
- Can be used to provide users with information about the location of the entity
  they are communicating with (i.e. the endpoint on the other side of the path)
- Informing network admins about router locations

#### Conceptual Implementation Geographic Information

The geographic information will be comprised of 2 main parts: - The subtype
field, which identifies it - A variable number of location clusters

A location cluster serves to pool all interfaces which are located in the same
geographic location (i.e. same address). Each location cluster is itself formed
of 2 main types of elements:

- The location of the cluster, consisting of a pair of GPS coordinates
  describing latitude and longitude, as well as a civic address, in the format
  specified in RFC 4776 (found
  <a href = "https://tools.ietf.org/html/rfc4776#section-3.3"> here </a>)
  (1 value in total)
- The interface ID for every interface in the cluster (1 value per interface)

### Link Type

#### Definition Link Type

The Link Type is defined as follows:

> Link Type information gives a broad classification of the different protocols
> being used on the links between two entities.

For now it distinguishes three different types of links:

- Links that go over the open internet
- Direct links
- Multihop links

#### Use Cases Link Type

- Mitigating security concerns
- Allowing users to select paths that e.g. avoid the open internet

#### Conceptual Implementation Link Type

The Link type will be comprised of 2 parts:

- The subtype field, which identifies it
- A variable number of link type clusters

A link type cluster serves to pool all interfaces which are attached to an
intra-AS link and have a connection of the same link type between them and the
egress interface. Each link type cluster is itself comprised of 3 types of
elements:

- The link type for every interface in the cluster (1 value per cluster)
- The interface ID for every interface in the cluster (1 value per interface)
- The inter-AS link type for the connection attached to the interface (1 value
  per interface)

### Maximum Bandwidth

#### Definition Maximum Bandwidth

Maximum Bandwidth Information consists of 2 parts, Inter- and Intra-AS and is
defined as follows:

> Inter-AS Maximum Bandwidth Information describes the maximum bandwidth
> available on the inter-AS connections between each AS on an end-to-end path.
> Intra-AS Maximum Bandwidth Information describes the smallest maximum
> bandwidth available on any link that lies on the intra-AS routing path.

#### Use Cases Maximum Bandwidth

- Allows to augment path selection policy, such that unsuitable paths can be
  excluded a priori
- Avoid connections that are prone to congestion due to a low-bandwidth
  bottleneck somewhere

#### Conceptual Implementation Maximum Bandwidth

The maximum bandwidth information will be comprised of 2 main parts: - The
subtype field, which identifies it - A variable number of maximum bandwidth
clusters

Each cluster is itself formed of 3 types of elements:

- The minimum across all maximum bandwidths of all connections on the path from
  the cluster to the current interface (1 value per cluster)
- The interface ID of the interface
- The maximum bandwidth of the inter-AS link attached to the interface

### Number of Internal Hops

#### Definition Number of Internal Hops

The Number of Internal Hops is defined as follows: > The Number of Internal Hops
describes how many hops are on the Intra-AS path.

#### Use Cases

- Can be used to exclude undesireable paths from the selection
- Obtain a selection of efficient, low latency paths (especially when combined
  with Latency Information)

#### Conceptual Implementation

The number of internal hops will be comprised of 2 main parts:

- The subtype field, which identifies it
- A variable number of hoplength clusters

A hoplength cluster serves to pool all interfaces which have the same number of
internal hops on the path between them and the egress interface. Each hoplength
cluster is itself formed of 2 main elements:

- The number of internal hops for every interface in the cluster (1 value per
  cluster)
- The interface ID for every interface in the class (1 value per interface)

### Note

#### Definition Note

The Note is defined as follows:

> A bit of plaintext.

#### Use Cases Note

- Tool for network engineers to communicate interesting/important information to
  their peers as well as users

#### Conceptual Implementation Note

The Note subtype is comprised of 2 elements:

- The subtype field, which identifies it
- The text field, which contains the contents of the note

### Metadata Endpoint

#### Definition Metadata Endpoint

Metadate Endpoint Information is defined as follows:

> A URL which can be used to fetch additional metadata (i.e. the aforementioned
> as well as additional (non-)static properties describing the (topology of the)
> AS whose AS Entry it extends.

#### Use Cases Metadata Endpoint

- Decreases size of PCB
- Supply additional data that might not have its own extension yet
- Less Information needs to be included in the PCB itself

#### Conceptual Implementation Metadata Endpoint

The metadata endpoint subtype is comprised of 2 elements:

- The subtype field, which identifies it
- The url field, which contains the url

## Concrete Implementation

Cap'nProto will be used for the wire formats of the extension[??? Ask in slack
about this]. The following section is devoted to looking at the implementation
of each property in detail.

### Wire Format Overall

The following chart illustrates the overall format of the extension:

`Type` | `Latency` | `GeoInfo` | `LT` | `MBW` | `NIH` | `Note` | `ME` |
-------|-----------|-----------|------|-------|-------|--------|------|

Except for `Type` at the beginning, all of these fields are optional.

### Wire Formats Subtypes

#### Latency Format

The wire format for latency information looks like this:

`SubType` | `LC_1` | `LC_2` | ... | `LC_n` |
----------|--------|--------|-----|--------|

Each `LC_i` field looks as follows:

`ClusterDelay_i` | `ID_i_0` | `InterDelay_i_0` | ... | `ID_i_m` | `InterDelay_i_m` |
-----------------|----------|------------------|-----|----------|------------------|

The table below shows names, types and lengths (in bytes) of each value:

Name               | Type | Length |
-------------------|------|--------|
`SubType`          |UInt8 |1       |
`ClusterDelay_i`   |UInt16|2       |
`ID_i_j`           |UInt8 |1       |
`Interdelay_i_j`   |UInt16|2       |

#### Geographic Information Format

The wire format for geographic information looks like this:

`SubType` | `GC_1` | `GC_2` | ... | `GC_n` |
----------|--------|--------|-----|--------|

Each `GC_i` field looks as follows:

`ClusterLocation_i` | `ID_i_0` | ... | `ID_i_m` |
--------------------|----------|-----|----------|

A `ClusterLocation_i` field looks like this:

`GPS_i_0` | `GPS_i_1` | `CivAdd` |
----------|-----------|----------|

The table below shows names, types and lengths (in bytes) of each value:

Name               | Type  | Length |
-------------------|-------|--------|
`SubType`          |UInt8  |1       |
`GPS_i_0`          |Float32|4       |
`GPS_i_0`          |Float32|4       |
`CivAdd`           |Data   |100     |
`ID_i_j`           |UInt8  |1       |

#### Link Type Format

The wire format for the link type looks like this:

`SubType` | `LT_1` | ... | `LT_n` |
----------|--------|-----|--------|

Each `LT_i` field looks as follows:

`ClusterLinkType_i` | `ID_i_0` | `InterLink_i_0` | ... | `ID_i_m` | `InterLink_i_m` |
--------------------|----------|-----------------|-----|----------|-----------------|

The table below shows names, types and lengths (in bytes) of each value:

Name                | Type | Length |
--------------------|------|--------|
`SubType`           |UInt8 |1       |
`ClusterLinkType_i` |Uint8 |1       |
`ID_i_j`            |UInt8 |1       |
`InterLink_i_j`     |UInt8 |1       |

#### Maximum Bandwidth Format

The wire format for maximum bandwidth information looks like this:

`SubType` | `MBC_1` | `MBC_2` | ... | `MBC_n` |
----------|---------|---------|-----|---------|

Each `MBC_i` field looks as follows:

`ClusterBW_i` | `ID_i_0` | `InterBW_i_0` | ... | `ID_i_m` | `InterBw_i_m` |
--------------|----------|---------------|-----|----------|---------------|

The table below shows names, types and lengths (in bytes) of each value:

Name               | Type | Length |
-------------------|------|--------|
`SubType`          |UInt8 |1       |
`ClusterBW_i`      |UInt32|4       |
`ID_i_j`           |UInt8 |1       |
`InterBW_i_j`      |UInt32|4       |

#### Number of Internal Hops Format

The wire format for the number of internal hops looks like this:

`SubType` | `HC_1` | `HC_2` | ... | `HC_n` |
----------|--------|--------|-----|--------|

Each `HC_i` field looks as follows:

`ClusterHops_i` | `ID_i_0` | ... | `ID_i_m` |
----------------|----------|-----|----------|

The table below shows names, types
and lengths (in bytes) of each value:

Name               | Type | Length |
-------------------|------|--------|
`SubType`          |UInt8 |1       |
`ClusterHops_i`    |UInt8 |1       |
`ID_i_j`           |UInt8 |1       |

#### Note Format

The wire format for the note looks like this:

`SubType` | `Words` |
----------|---------|

The table below shows names, types and lengths (in bytes) of each value:

Name               | Type | Length |
-------------------|------|--------|
`SubType`          |UInt8 |1       |
`Words`            |Text  |100     |

#### Metadata Endpoint Format

The wire format for the metadata endpoint looks like this:

`SubType` | `URL` |
----------|-------|

The table below shows names, types and lengths (in bytes) of each value:

Name               | Type | Length |
-------------------|------|--------|
`SubType`          |UInt8 |1       |
`URL`              |Text  |100     |

### Config File Format

In order for the extension to work, a config file needs to be provided to a
specific location [tbd]. The config file comes in the form of a txt file
and needs to have the format illustrated below. First of all, we have the
following two values:

Name               | Type  | Description |
-------------------|-------|-------------|
`N`                |Integer|Number of interfaces in the AS|
`IntfIDs`          |List of Integers|Interface IDs of
every interface in the AS, ordered in ascending order|

Then, for every interface listed above, in the same order as in the `IntfIDs`
list, follow, for every interface `i` the following values:

Name               | Type  | Description |
-------------------|-------|-------------|
`IntfStart`| String (Special flag) | Signifies beginning of new interface, to be written exactly as in the name field|
`Lat`      |String (Special flag) |Signifies beginning of latency section, to be written exactly as in the name field|
`IntraLatency`     |List of N Integers|Intra-AS latency from interface `i` to every other interface in the AS, including itself (this entry is set to 0)|
`InterLatency`     |Integer|Inter-AS latency from interface `i` to AS on the other end of the link|
`Geo`     |String (Special flag) |Signifies beginning of geographic information section, to be written exactly as in the name field|
`C1_i`             |Decimal value|Longitude gps coordinates of interface `i`|
`C2_i`             |Decimal value|Latitude gps coordinate of interface `i`|
`CivAddrStart`     |String (Special flag)| string that specifies beginning of civil address of interface `i`|
`CivAddr_i`        |Data|Civic address of interface `i`|
`CivAddrStop`      |String (Special flag)| string that specifies end of civil address of interface `i`|
`Link`     |String (Special flag) |Signifies beginning of link type section, to be written exactly as in the name field|
`IntraLink_i`      |List of Enums |Possible values of a list entry : `Multi`, `Direct`, `OpenNet`; Describes link type between interface `i` and any other interface, including itself (this entry is set to `direct`)|
`InterLink_i`      |Enum  |Possible values of a list entry : `Multi`, `Direct`, `OpenNet`; Describes link type between interface `i` and the AS at the other end of the link|
`BW`     |String (Special flag) |Signifies beginning of bandwidth section, to be written exactly as in the name field|
`IntraBW_i`        |List of Integers|Intra-AS bandwidth from interface `i` to every other interface in the AS, including itself (this entry is set to 0)|
`InterBW_i` |Integer|Inter-AS bandwidth from interface i to the AS at the other end of the link|
`Hop` |String (Special flag) |Signifies beginning of number of internal hops section, to be written exactly as in the name field|
`Hops_i` |List of Integers|Number of internal hops from interface `i` to every other interface in the AS, including itself (this entry is set to 0)|

Then, after every interface has been listed, follow a few final fields:

Name               | Type  | Description |
-------------------|-------|-------------|
`IntfsEND`          |String|Special flag string that specifies end of the interface section|
`NoteStart`|String|Special flag string that specifies beginning of Note contents|
`Note` |String|Note|
`NoteStop`         |String|Special flag string that specifies end of Note contents|
`URL`     |String (Special flag) |Signifies beginning of metadata endpoint section, to be written exactly as in the name field|
`URLContents`      |String|URL for metadata endpoint|

The special flag strings have to be written exactly as shown in the name field.
Values are separated by whitespaces.

Below is a simple example of how such a config file could look like (actual
values are abitrary) for an AS with three interfaces with IDs 1, 2 and 3:

````Java
3
1 2 3
IntfStart
Lat
0 10 20
30
Geo
45.7
46.9
CivAddrStart
//civil address goes here
CivAddrStop
Link
Direct Multi Direct
OpenNet
BW
0 200000000 100000000
150000000
Hop
0 2 4
IntfStart
Lat
10 0 20
30
Geo
84.3
32.9
CivAddrStart
//civil address goes here
CivAddrStop
Link
Multi Direct Direct
OpenNet
BW
200000000 0 300000000
250000000
Hop
1 0 5
IntfStart
Lat
10 10 0
40
Geo
54.3
62.9
CivAddrStart
//civil address goes here
CivAddrStop
Link
Multi Direct Direct
Direct
BW
200000000 300000000 0
50000000
Hop
1 2 0
IntfsEND
NoteStart
//note goes here (should not contain the word "NoteStop")
NoteStop
URL
//url goes here
````
