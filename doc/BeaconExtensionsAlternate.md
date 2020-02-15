# Embedding Static Information in SCION Beacons

In order to estimate certain properties of a SCION path segment, a hash which can
be used to fetch information about static properties of that path can be embedded
inside the path construction beacons in the form of an extension.

## Table of Contents

- [Static Properties](#static-properties)
- [Format Overall](#format-overall)
- [Latency Information](#latency-information)
    - [Conceptual Implementation Latency](#conceptual-implementation-latency)
    - [Concrete Format Latency](#concrete-format-latency)
- [Geographic Information](#latency-information)
    - [Conceptual Implementation Geographic Information](#conceptual-implementation-geographic-information)
    - [Concrete Format Geographic Information](#concrete-format-geographic-information)
- [Link Type](#link-type)
    - [Conceptual Implementation Link Type](#conceptual-implementation-link-type)
    - [Concrete Format Link Type](#concrete-format-link-type)
- [Maximum Bandwidth](#maximum-bandwidth)
    - [Conceptual Implementation Maximum Bandwidth](#conceptual-implementation-maximum-bandwidth)
    - [Concrete Format Maximum Bandwidth](#concrete-format-maximum-bandwidth)
- [Number of Internal Hops](#number-of-internal-hops)
    - [Conceptual Implementation Number of Internal Hops](#conceptual-implementation-number-of-internal-hops)
    - [Concrete Format Number of Internal Hops](#concrete-format-number-of-internal-hops)
- [Note](#note)
    - [Conceptual Implementation Note](#conceptual-implementation-note)
    - [Concrete Format Note](#concrete-format-note)
- [Metadata Enbpoint](#metadata-endpoint)
    - [Conceptual Implementation Metadata Endpoint](#conceptual-implementation-metadata-endpoint)
    - [Concrete Format Metadata Endpoint](#concrete-format-metadata-endpoint)
- [Config File Format](#config-file-format)
- [Concrete Implementation](#concrete-implementation)

## Static Properties

For the purpose of this document, we will adhere to the following definition:
A static property is any quantifiable piece of information describing a
property of a SCION path segment that remains unchanged over the entire
duration of the lifetime of that path segment.

The following assumptions are made:

- The Beacon Service, which is responsible for adding all this metadata, has
  reliable information about the infrastructure (such as the border routers
  and the interfaces attached to them)
- The Beacon Service has access to a blackbox (which could be the AS itself,
  a dedicated SCION service or any other entity), which provides information
  that characterizes the AS topology and the routing processes within the AS
- The AS topology remains stable throughout the lifetime of a path segment

When discussing static properties, we always need to distinguish between
inter-AS and intra-AS elements. Most properties will be comprised of both.
Using the diagram below, the concept of this difference between intra-AS
and inter-AS elements will be illustrated with the example of propagation
delay.

![Inter VS Intra Metrics](fig/inter_vs_intra_metrics.png)

The PCB originates in AS 3, and is then propagated to AS 1, and then to
AS 2. In the AS Entry of AS 1, interface 1 is the ingress and inteface 2
the egress interface. In order to be able to calculate the end-to-end
propagation delay of a path starting in AS 2 and ending in AS 3, we need
both the delay inside each AS (intra-AS), as well as the delay on the
connections between ASes (inter-AS). Recall that in this scenario intra-AS
latency refers to the delays between an interface and the egress interface
(i.e. the egress interface is the "target" interface to which latency is
measured from any other interface). As the figure shows, interface 1 is
attached to both an intra-AS connection as well as an inter-AS connection.
We therefore need to store both the intra- and the inter-AS metrics.
As can be seen when looking at the diagram,
this means that for every AS we then have the delay inside the AS, and the
delay from  the AS whose AS entry we are extending (i.e. the current AS) to
the AS the PCB will be propagated to next (i.e. the next AS). Using this
method, we can then calculate the end-to-end delay
by simply combining intra- and inter-AS delays. This concept applies
similarly to many other properties.
We will now explore the general concept of this approache, before looking at all the
properties we will store and the information that
needs to be provided for each of them.

## General Concept

This functionality allows for a hash to be included in the extension field of the AS Entry
of the PCB. This hash identifies a location in a path server (either local or remote),
where information about the static properties is stored in the form of a config file.
When an end host tries to reach a destination, it will fetch path segements (which are
simply modified PCBs) and construct an end to end path. Once this path is constructed,
the hashes in the PCBs can then be used to fetch the relevant pieces of information
about the static properties of this end-to-end path from their respective locations.
Once fetched, the information can be "assembled" and used to e.g. calculate propagation
delays on the path.
Next we will look at which static properties we will use and what information in particular
we will store.

## Latency Information

Latency Information refers to the total propagation delay on an end to end
path, comprised of intra- and inter-AS delays and measured on the scale of
milliseconds.
Use cases of such information include:

- Allows to augment path selection policy in order to obtain low latency paths
- Shortening the duration it takes to fetch data and thus decreasing wait times
  for the user
- Time critical applications

### Conceptual Implementation Latency

The latency information will be comprised of 2 main parts:

- The inter-AS latency between every interface of this AS and the ingress interface of
  the AS on the other side of the connection
- The intra-AS latency between every pair of interfaces in the AS whose AS Entry
  is being extended

Information about the inter-AS latency, as well as the intra-AS latency from
every interface to the egress interface is required to deal with certain types of paths.

![Normal Path](fig/normal_path.png)

In the case of a "normal" path, the interfaces where traffic enters
and leaves correspond to the ingress and egress interfaces respectively, that are
saved in the AS Entry of the PCB. The terms ingress and egress interfaces refer to
the way these interfaces would be encoded in the PCB during the beaconing process,
therefore the lower interface is always labelled as the egress interface, even when it is in
the up segment and would thus technically be the interface on which traffic enters the AS.
Calculating end-to-end latencies can therefore be done by simply adding up the intra-AS
latency (from ingress to egress interface) as well as the inter-AS latency (from egress
interface to the next AS on the path) for every AS on the end to end path.

Knowing merely the inter-AS latency for the egress interface is also sufficient
in the case of shortcut paths. The interface where traffic will enter AS 2
is the egress interface saved in the AS Entry for AS 2 in the PCB which was directly
received by AS 3. The interface where traffic will leave AS 2 is the interface that
was saved in AS Entry of the PCB that was sent to AS 4 and was fetched by AS 3 in
the form of a path segment during the path lookup process. Thus AS 3 now has information
about both the inter-AS connection between AS 3 and AS 2, and the inter-AS connection
between AS 2 and AS 4. In the presence of information about intra-AS latencies, 
this information is sufficient to calculate the end-to-end latency betwen AS 3 and AS 4
(see figure below). 

Peering connections however introduce a problem. A peering link may differ
from the egress interface encoded in any of the AS Entries of any of the path segments that
were received or fetched by AS 3. Therefore we need to make sure that the inter-AS latency
for every connection attached to a peering interface of the AS is also stored (see figure below).
Since at the time of storing the information we do not necessarily know which interface will be
the egress interface, and we need to deal with peering connections,
we will simply store the inter-AS latency for every interface in the AS.

Intra-AS delays present a problem in the presence of both shortcut-, or peering
paths. In those situations, merely 
storing the latency from the ingress to the egress interface will be insufficient.
This is because the interface on which traffic will leave the AS as it travels
along the path will no longer be the ingress interface encoded in the PCB that
was used to construct the up segment, but rather either the egress interface
stored in a different PCB (in the case of a shortcut connection) or a peering
interface (in the case of a peering conncetion). Therefore, it is necessary
that latencies (or other metrics when looking at a different property) be known
for the paths from the egress interface to such a non-ingress interface also
(see figure below).

![Shortcut Path](fig/shortcut_path.png)
![Peering Path](fig/peering_path.png)

Because of this we will store the intra-AS latency between every pair of interfaces.
All these considerations also apply to other properties, such as maximum bandwidth
(see below).

## Maximum Bandwidth

Maximum Bandwidth Information consists of 2 parts, Inter- and Intra-AS:

- Inter-AS Maximum Bandwidth Information describes the maximum bandwidth
  available on the inter-AS connections between each AS.
- Intra-AS Maximum Bandwidth Information describes the smallest maximum
  bandwidth available on any link that lies on the intra-AS routing path,
  i.e. the path from an interface to the egress interface.
  
Bandwidth is measured at the granularity of Kb/s.
Use cases of such information include:

- Allows to augment path selection policy, such that unsuitable paths can be
  excluded a priori
- Avoid connections that are prone to congestion due to a low-bandwidth
  bottleneck somewhere

### Conceptual Implementation Maximum Bandwidth

The maximum bandwidth information will be comprised of 2 main parts:

- The inter-AS maximum bandwidth between every interface and the 
  AS on the other side of the connection
- The intra-AS maximum bandwidth between every pair of interfaces in the AS

## Geographic Information

Geographic Information is the full set of GPS coordinates identifying the
location of every SCION border router deployed by an AS, as well as a real
life address associated with the location of each such SCION border router.
Use cases of such information include:

- Can be used to augment path selection policies in order to ensure paths do not
  leave a particular area, or alternatively ascertain that they never cross
  territory that is considered "undesirable" by the user
- Can be used to provide users with information about the location of the entity
  they are communicating with (i.e. the endpoint on the other side of the path)
- Informing network admins about router locations

### Conceptual Implementation Geographic Information

The geographic information will be comprised of only a single type of element:

- A variable number of locations (1 per interface)

Each location contains the following:

- A pair of GPS coordinates
  describing latitude and longitude
- A civic address, in the format
  specified in RFC 4776 (found
  <a href = "https://tools.ietf.org/html/rfc4776#section-3.3"> here </a>)

It is possible to use only the latititude and longitude pair, or the civic
address by simply omitting one of the two.

## Link Type

### Definition Link Type

Link Type information gives a broad classification of the different protocols
being used on the links between two entities.
For now it distinguishes four different types of links:

- Links that go over the open internet
- Direct links
- Multihop links
- Undisclosed

The option to have undisclosed link types allows ASes to withhold such
information should they deem it undesirable to make it available to the
public. Use cases of such information include:

- Mitigating security concerns
- Allowing users to select paths that e.g. avoid the open internet

### Conceptual Implementation Link Type

The Link type will be comprised of 2 parts:

- The link type for the inter-AS link attached to every interface in the AS
- The intra-AS link type between every pair of interfaces in the AS

## Number of Internal Hops

The Number of Internal Hops describes how many hops are on the Intra-AS path.
Use cases of such information include:

- Can be used to exclude undesireable paths from the selection
- Obtain a selection of efficient, low latency paths (especially when combined
  with Latency Information)

### Conceptual Implementation Number of Internal Hops

The number of internal hops will be stored as

- The number of internal hops between every pair of interfaces in the AS

## Note

A Note is simply a bit of plaintext.
Use cases of such information include:

- Tool for network engineers to communicate interesting/important information to
  their peers as well as users

### Conceptual Implementation Note

The Note subtype is comprised of 2 types of elements:

- The "default" field, which contains a default note, which is always included for
  every PCB that is propagated by this AS.
- The "specific" field, which contains the contents of a note that is meant to only
  be attached when sending out a PCB over the particular interface mentioned in the
  egress interface field of the AS Entry that we are extending.
  
When constructing the extension from the config file (see below) the BS will check
the egress interface field in the AS Entry and attach the "specific" note accordingly.
If no such note is specified in the config file, then the contents of the "specific"
field will be set to null (it is also possible to do this for the "default" note as
well.

## Config File Format

In order for the extension to work, a config file needs to be provided to a
specific location [tbd]. The config file comes in the form of a JSON file.
Taking into consideration the above explanations, the format of the config 
file will need to be as shown below. First of all, we have the
following value:

Name               | Type  | Description |
-------------------|-------|-------------|
`N`                |Integer|Number of interfaces in the AS|

Then, for every interface `i` the following values can be provided:

Name             | Type  | Description |
-----------------|-------|-------------|
`IntfID`         |Integer|Interface ID of the interface described by the data that follows|
`IntraLatency`   |List of N Integers|Intra-AS latency from interface `i` to every other interface in the AS, including itself (this entry is set to 0)|
`InterLatency`   |Integer|Inter-AS latency from interface `i` to AS on the other end of the link|
`C1`             |Decimal value|Longitude gps coordinates of interface `i`|
`C2`             |Decimal value|Latitude gps coordinate of interface `i`|
`CivAddr`        |String|Civic address of interface `i`|
`IntraLink`      |List of Integers |Describes link type between interface `i` and any other interface, including itself (this entry is set to 0), where 0 means direct link, 1 means multihop link and every other number means link that uses the open internet|
`InterLink`      |Integer  |Possible values of a list entry : `Multi`, `Direct`, `OpenNet`; Describes link type between interface `i` and the AS at the other end of the link|
`IntraBW`        |List of Integers|Intra-AS bandwidth from interface `i` to every other interface in the AS, including itself (this entry is set to 0)|
`InterBW`        |Integer|Inter-AS bandwidth from interface i to the AS at the other end of the link|
`SpecificNote`   |String |Note that should be used when this interface is the egress interface in the AS Entry that is being extended|
`Hops`           |List of Integers|Number of internal hops from interface `i` to every other interface in the AS, including itself (this entry is set to 0)|

Then, after every interface has been listed, follow a few final fields:

Name               | Type  | Description |
-------------------|-------|-------------|
`DefaultNote`      |String |Default Note|
`URLContents`      |String |URL for metadata endpoint|

Below is a simple example of how such a config file could look like (actual
values are abitrary, "asdf" is used as a placeholder for longer strings)
for an AS with three interfaces with IDs 1, 2 and 3:

````JSON
{
  "N": 3,
  "Interfaces": [{
    "IntfID": 1,
    "IntraLatency": [0, 10, 20],
    "InterLatency": 30,
    "C1": 45.7,
    "C2": 25.9,
    "CivAddr": "asdf",
    "IntraLink": [0,1,0],
    "InterLink": 2,
    "IntraBW": [0, 200000000, 100000000],
    "InterBW": 150000000,
    "SpecificNote": "asdf",
    "Hops": [0, 2, 4]
  },{
    "IntfID": 2,
    "IntraLatency": [10, 0, 20],
    "InterLatency": 40,
    "C1": 34.7,
    "C2": 27.2,
    "CivAddr": "asdf",
    "IntraLink": [1,0,2],
    "InterLink": 2,
    "IntraBW": [200000000, 0, 100000000],
    "InterBW": 450000000,
    "Hops": [1, 0, 4]
  },{
    "IntfID": 3,
    "IntraLatency": [10, 40, 0],
    "InterLatency": 10,
    "C1": 66.2,
    "C2": 37.0,
    "CivAddr": "asdf",
    "IntraLink": [1,1,0],
    "InterLink": 1,
    "IntraBW": [200000000, 300000000, 0],
    "InterBW": 50000000,
    "SpecificNote": "asdf",
    "Hops": [1, 0, 0]
  }],
  "DefaultNote": "asdf",
  "URL": "asdf"
}
````

## Concrete Implementation

This section will be devoted to looking at the details of the system
that stores and fetches the static properties, as well as the implementation
of the extension itself.

### Config File Location

Asdf.

### Fetching Mechanism

Asdf.

### Extension Wire Format

Cap'nProto will be used for the wire formats of the extension. 

