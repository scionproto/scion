# Embedding Static Information in SCION Beacons

The following document will explore ways to embed static information into SCION
path construction beacons (PCBs). It will first give a definition of what is
considered to be "static information" in the context of this work, before
exploring 7 particular static properties, how to define them and how to
implement them as part of the SCION infrastructure.

## Static Properties

For the purpose of this document, we will adhere to the following definition of
a static property:
>A static property is any quantifiable piece of information describing a
>property of a SCION path segment that remains unchanged over the entire
>duration of the lifetime of that path segment.

This definition a priori excludes ephemeral metrics like currently available
bandwidth for example, since this property will frequently change over the
course of the lifetime of a path segment. Furthermore, it precludes capturing
*internal* metrics describing the source- respectively destination AS. (There
are still some properties that can describe source/destination ASes, see e.g.
Geographic Information below.) Before proceeding, it shall be explicitly stated
here that for the purpose of this work, the following assumptions are made:

- SCION has reliable information about its own infrastructure
- SCION has access to a blackbox (which could be the AS itself, a dedicated
  SCION service or any other entity), which provides information that
  characterizes the AS topology and the routing processes within the AS
- The AS topology remains stable throughout the lifetime of a path segment

To simplify the following discussion of the conceptual implementation of each
property, this document will briefly recapitulate the conceptual structure of a
PCB, which will provide the basis for the implementation provided thereafter.
Conceptually, a PCB looks like this:
<a href="https://www.codecogs.com/eqnedit.php?latex=PCB&space;=&space;\langle&space;INF&space;\|ASE_0&space;\|&space;ASE_1&space;\|&space;...&space;\|&space;ASE_n&space;\rangle" target="_blank"><img src="https://latex.codecogs.com/svg.latex?PCB&space;=&space;\langle&space;INF&space;\|ASE_0&space;\|&space;ASE_1&space;\|&space;...&space;\|&space;ASE_n&space;\rangle" title="PCB = \langle INF \|ASE_0 \| ASE_1 \| ... \| ASE_n \rangle" /></a>
For the purpose of this thesis, we will
only look at the parts that are of importance to the task at hand. We therefore
disregard the INF field and have a look at the structure of the AS entries
ASE<sub>0</sub> to ASE<sub>n</sub>. Each AS entry is internally structured like
this: 
<a href="https://www.codecogs.com/eqnedit.php?latex=ASE&space;=&space;\langle&space;Meta&space;\|&space;HE&space;\|&space;PE_0&space;\|&space;PE_1&space;\|&space;...&space;\|&space;PE_m&space;\|&space;RevToken&space;\|&space;Ext&space;\|&space;\Sigma&space;\rangle" target="_blank"><img src="https://latex.codecogs.com/svg.latex?ASE&space;=&space;\langle&space;Meta&space;\|&space;HE&space;\|&space;PE_0&space;\|&space;PE_1&space;\|&space;...&space;\|&space;PE_m&space;\|&space;RevToken&space;\|&space;Ext&space;\|&space;\Sigma&space;\rangle" title="ASE = \langle Meta \| HE \| PE_0 \| PE_1 \| ... \| PE_m \| RevToken \| Ext \| \Sigma \rangle" /></a>
The Meta-field, as its name suggests,
serves mainly to encode some metadata about the AS, such as which ISD it is
located in or what the MTU inside the AS is. The HE-field is the hop entry,
which specifies over which ingress interface packets should arrive in the AS and
over what egress interface they should leave again. The PE-fields are the peer
entries and serve a similar function as the hop entry, except that they encode
the interfaces of peering connections as the ingress interface. Next follows the
revocation token, which can be used to revoke any interface of the entry in an
authenticated manner. After that comes the Ext-field, that
is meant to house extensions, which we will soon look at in greater detail. And
lastly comes the signature used to authenticate each AS entry. For the purpose
of embedding static information in the SCION beacons, the Ext-field is the
obvious choice. For one thing, it requires only minimal modification of the
beacons themselves. For another, since the Ext-field is signed, the integrity
of the encoded information is guaranteed. Every extension field starts with its
type encoded in 1 byte. After that comes the payload, i.e. the
actual contents of the extension. In order to keep things simple while at the
same time retaining as much versatility as possible, we will introduce the type
"Static Property", which will be denoted by a specific combination of 8 bits in
the Type field of the extension. The payload of a Static Property extension will
itself start with another special "subtype" field, which denotes which property
in particular is encoded in the rest of the payload. This scheme is used for 2
reasons. First, there is, at time of writing, no obligation on the part of the
AS to include any Static Property fields whatsoever. Thus, the AS can decide for
itself which, if any, static properties it wishes to embed into its AS Entry in
the PCB. This format provides the necessary flexibility to allow for this.
Second, this approach is easily extended should one want to include new
properties beyond the scope of this work in the future. The subtype field will
take up 1 byte at the very start of the payload. We will now discuss the
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

When it comes to the subtype field, we will for now simply number each property
from 1 through 7. Thus the subtype field for Latency Information will be set to
the binary representation of 1, i.e. 00000001. The actual payload of the
extension will be structured as shown in the following diagram:
<a href="https://www.codecogs.com/eqnedit.php?latex=LI&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;...&space;\|&space;BR_n&space;\rangle" target="_blank"><img src="https://latex.codecogs.com/svg.latex?LI&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;...&space;\|&space;BR_n&space;\rangle" title="LI = \langle ST \| Len \| BR_1 \| ... \| BR_n \rangle" /></a>
It starts with the subtype field ST.
Next comes the Len field, which is 2 bytes long, and represents a uint that
denotes the number of BRs in the AS the AS Entry to which this extension is
attached is referring to. Now follow a total of Len BR_i-fields. Each BR_i
field is itself divided into parts as shown below:
<a href="https://www.codecogs.com/eqnedit.php?latex=BR_i&space;=&space;\langle&space;\|&space;TotMs&space;\|&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;IntfMs_1&space;...&space;\|&space;IntfID_n&space;\|&space;IntfMs_n&space;\rangle" target="_blank"><img src="https://latex.codecogs.com/svg.latex?BR_i&space;=&space;\langle&space;\|&space;TotMs&space;\|&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;IntfMs_1&space;...&space;\|&space;IntfID_n&space;\|&space;IntfMs_n&space;\rangle" title="BR_i = \langle \| TotMs \| NrIntfs \| IntfID_1 \| IntfMs_1 ... \| IntfID_n \| IntfMs_n \rangle" /></a>
The TotMs field describes the latency between the egress interface and any interface
attached to this BR (it will be set to 0 for the BR which the egress interface
is attached to). This implies the assumption that the the latency is identical
(or at least the differences are negligibly small) for every connection between
the egress interface and any other interface attached to the same BR. The
NrIntfs field is 1 byte long and is to be interpreted as an unsigned integer
that describes the number of interfaces attached to BR_i. Each IntfID_i
field denotes the address of an interface and is 1 byte long, while the IntfMs_i
fields refer to the latency of the link attached to this interface,
once again in the form of a 16 bit uint that denotes the latency in Ms.
We need the latency to each BR in order to be able to deal with the
case of SCION paths that make use of shortcuts or peering
connections. To summarize, the space required by the Latency Information
extension in bytes is calculated as the sum of the amount of space consumed by
the ST field, the InIntf field, the Len field and the Len Br_i fields.
The size of each BR_i field can be bounded from above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[BR_i]&space;=&space;Size[TotMs]&space;&plus;&space;Size[NrIntfs]&space;\\&space;&plus;&space;(NrIntfs&space;\times&space;(Size[IntfID_i]&space;&plus;&space;Size[IntfMs_i]))&space;\\&space;\leq&space;2&space;&plus;&space;2&space;&plus;&space;(NrIntfs&space;\times&space;(1&plus;2))&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[BR_i]&space;=&space;Size[TotMs]&space;&plus;&space;Size[NrIntfs]&space;\\&space;&plus;&space;(NrIntfs&space;\times&space;(Size[IntfID_i]&space;&plus;&space;Size[IntfMs_i]))&space;\\&space;\leq&space;2&space;&plus;&space;2&space;&plus;&space;(NrIntfs&space;\times&space;(1&plus;2))&space;$$" title="$$ Size[BR_i] = Size[TotMs] + Size[NrIntfs] \\ + (NrIntfs \times (Size[IntfID_i] + Size[IntfMs_i])) \\ \leq 2 + 2 + (NrIntfs \times (1+2)) $$" /></a>
bytes. Thus the total size of the extension field in bytes is bounded from above
by
<a href="https://www.codecogs.com/eqnedit.php?latex=Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(Len&space;\times&space;4)&space;&plus;&space;\sum_1^{Len}&space;(&space;NrIntfs_i&space;\times&space;(1&plus;2))&space;\\&space;=&space;3&space;&plus;&space;(4&space;\times&space;Len)&space;&plus;&space;((1&plus;2)&space;\times&space;TotIntfs)" target="_blank"><img src="https://latex.codecogs.com/svg.latex?Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(Len&space;\times&space;4)&space;&plus;&space;\sum_1^{Len}&space;(&space;NrIntfs_i&space;\times&space;(1&plus;2))&space;\\&space;=&space;3&space;&plus;&space;(4&space;\times&space;Len)&space;&plus;&space;((1&plus;2)&space;\times&space;TotIntfs)" title="Size[Ext] = Size[ST] + Size[Len] + Size[BR_1] + ... + Size[BR_n] \\ \leq 1 + 2 + (Len \times 4) + \sum_1^{Len} ( NrIntfs_i \times (1+2)) \\ = 3 + (4 \times Len) + ((1+2) \times TotIntfs)" /></a>

Where Len is equivalent to the number of BRs deployed by the AS and TotIntfs
is the total number of all interfaces attached to the BRs. This scheme provides
both the inter-AS latency on every incoming peering link, as well as the
intra-AS latency between the egress interface and any other interface. Thus it
supplies all the information necessary to calculate the total latency on the end
to end path even in the presence of peering or shortcut paths.

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

The following diagram shows the structure of the payload for this extension. 
<a href="https://www.codecogs.com/eqnedit.php?latex=GI&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;BR_2&space;\|&space;...&space;\|&space;...&space;\|&space;BR_n&space;\rangle" target="_blank"><img src="https://latex.codecogs.com/svg.latex?GI&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;BR_2&space;\|&space;...&space;\|&space;...&space;\|&space;BR_n&space;\rangle" title="GI = \langle ST \| Len \| BR_1 \| BR_2 \| ... \| ... \| BR_n \rangle" /></a>
It starts with the subtype field, which has a length of 1 byte
and for Geographic Information will be set to 2, i.e. 00000010.
Next is the Len field, which is 2 bytes long and denotes the
number of BRs in the AS the AS Entry is referring to. Now follow a total of
Len BR-fields. Each BR field is itself divided into parts as shown below:
<a href="https://www.codecogs.com/eqnedit.php?latex=BR_i&space;=&space;\langle&space;C_1&space;\|&space;C_2&space;\|&space;Addrlen&space;\|&space;Address&space;|\&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;...&space;\|&space;IntfID_n&space;\rangle" target="_blank"><img src="https://latex.codecogs.com/svg.latex?BR_i&space;=&space;\langle&space;C_1&space;\|&space;C_2&space;\|&space;Addrlen&space;\|&space;Address&space;|\&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;...&space;\|&space;IntfID_n&space;\rangle" title="BR_i = \langle C_1 \| C_2 \| Addrlen \| Address |\ NrIntfs \| IntfID_1 \| ... \| IntfID_n \rangle" /></a>
The C<sub>1</sub> and C<sub>2</sub> fields each denote a 32 bit float,
which refer to the GPS coordinates of the BR. The Addrlen field is 1 byte long
and is to be interpreted as an unsigned integer that describes the length of the
subsequent Address field. The Address field contains a string of ASCII
characters of maximum length 100, each encoded within 8 bytes. While this may
necessitate addresses to be expressed in roman letters (as opposed to e.g. the
native Chinese characters for a location in China), we chose to accept this
drawback in favor of a more compact representation. We decided to add the
Addrlen field since it allows us to increase the maximum possible
length of the Address itself, while requiring only a single byte (equivalent
to one additional character in the address) of extra space, and saving space
whenever the address does not require the maximum possible space. Then comes the
NrIntfs field, which is 2 bytes long and functions as a uint that denotes how
many interfaces are attached to this BR. Next follow NrIntfs IntfID<sub>i</sub>
entries, each of which is 1 byte long and refers to the ID of Interface i. To
summarize, the space required by the Geographic Information extension in bytes
is calculated as the sum of the amount of space consumed by the ST, the Len
field, and then the Len BR_i fields. The size of each BR_i field can be
bounded from above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[BR_i]&space;=&space;Size[C1]&space;&plus;&space;Size[C2]&space;&plus;&space;Size[Addrlen]&plus;&space;Size[Address]\\&space;&plus;&space;Size[NrIntfs]&space;&plus;&space;\sum_1^{NrIntfs}&space;Size[IntfID_i]\\&space;\leq&space;4&space;&plus;&space;4&space;&plus;&space;1&space;&plus;&space;100&space;&plus;&space;2&space;&plus;&space;NrIntfs&space;\\&space;=&space;109&space;&plus;&space;NrIntfs&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[BR_i]&space;=&space;Size[C1]&space;&plus;&space;Size[C2]&space;&plus;&space;Size[Addrlen]&plus;&space;Size[Address]\\&space;&plus;&space;Size[NrIntfs]&space;&plus;&space;\sum_1^{NrIntfs}&space;Size[IntfID_i]\\&space;\leq&space;4&space;&plus;&space;4&space;&plus;&space;1&space;&plus;&space;100&space;&plus;&space;2&space;&plus;&space;NrIntfs&space;\\&space;=&space;109&space;&plus;&space;NrIntfs&space;$$" title="$$ Size[BR_i] = Size[C1] + Size[C2] + Size[Addrlen]+ Size[Address]\\ + Size[NrIntfs] + \sum_1^{NrIntfs} Size[IntfID_i]\\ \leq 4 + 4 + 1 + 100 + 2 + NrIntfs \\ = 109 + NrIntfs $$" /></a>
bytes. Thus the total
size of the extension field in bytes is bounded from above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(Len&space;\times&space;109)&space;&plus;&space;TotIntfs&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(Len&space;\times&space;109)&space;&plus;&space;TotIntfs&space;$$" title="$$ Size[Ext] = Size[ST] + Size[Len] + Size[BR_1] + ... + Size[BR_n] \\ \leq 1 + 2 + (Len \times 109) + TotIntfs $$" /></a>
Where Len is equivalent
to the number of BRs deployed by the AS, and TotIntfs is the sum of the number
of all Interfaces attached to each BR.

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

The following diagram shows the structure of the payload for this extension: 
<a href="https://www.codecogs.com/eqnedit.php?latex=$LT&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;...&space;\|&space;BR_n&space;\rangle$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$LT&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;...&space;\|&space;BR_n&space;\rangle$" title="$LT = \langle ST \| Len \| BR_1 \| ... \| BR_n \rangle$" /></a>
It starts with the subtype
field, which has a length of 1 byte and for the Link Type will be set to 4, i.e.
00000100. Next is the $Len$ field, which is 2 bytes long and denotes the
number of BRs in the AS the current AS Entry is referring to. Now follow a total
of Len BR_i-fields. Each BR_i field is itself divided into parts as shown
below:
<a href="https://www.codecogs.com/eqnedit.php?latex=BR_i&space;=&space;\langle&space;BRLT&space;\|&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;IntfLT_1&space;\|&space;...&space;\|&space;IntfID_n&space;\|&space;IntfLT_n&space;\rangle" target="_blank"><img src="https://latex.codecogs.com/svg.latex?BR_i&space;=&space;\langle&space;BRLT&space;\|&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;IntfLT_1&space;\|&space;...&space;\|&space;IntfID_n&space;\|&space;IntfLT_n&space;\rangle" title="BR_i = \langle BRLT \| NrIntfs \| IntfID_1 \| IntfLT_1 \| ... \| IntfID_n \| IntfLT_n \rangle" /></a>
The BRLT field contains an enum of size 1 byte
that describes the type of the link between the egress interface and BR_i
(this value is set to zero for the case where BR_i is the same BR that the
egress interface is attached to), in terms of bits per second. The NrIntfs
field is 1 byte long and is to be interpreted as an unsigned integer that
describes the number of interfaces attached to BR_i. The IntfID_i fields
encode the interface ID in 1 byte. Each IntfLT_i field denotes a 1 byte
enum, which refers to the Link Type of the link attached to this interface. To
summarize, the space required by the Link Type extension in bytes is calculated
as the sum of the amount of space consumed by the ST, the Len field and  the
Len BR_i fields. The size of each BR_i field can be bounded from above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[BR_i]&space;=&space;Size[BRLT]&space;&plus;&space;Size[NrIntfs]&space;&plus;&space;Size[IntfID_1]&space;&plus;&space;...&space;&plus;&space;Size[IntfLT_n]&space;\\&space;\leq&space;1&space;&plus;&space;1&space;&plus;&space;X&space;&plus;&space;1&space;&plus;&space;...&space;&plus;&space;X&space;&plus;&space;1&space;=&space;2&space;&plus;&space;(NrIntfs&space;\times&space;(1&space;&plus;&space;X))\\&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[BR_i]&space;=&space;Size[BRLT]&space;&plus;&space;Size[NrIntfs]&space;&plus;&space;Size[IntfID_1]&space;&plus;&space;...&space;&plus;&space;Size[IntfLT_n]&space;\\&space;\leq&space;1&space;&plus;&space;1&space;&plus;&space;X&space;&plus;&space;1&space;&plus;&space;...&space;&plus;&space;X&space;&plus;&space;1&space;=&space;2&space;&plus;&space;(NrIntfs&space;\times&space;(1&space;&plus;&space;X))\\&space;$$" title="$$ Size[BR_i] = Size[BRLT] + Size[NrIntfs] + Size[IntfID_1] + ... + Size[IntfLT_n] \\ \leq 1 + 1 + X + 1 + ... + X + 1 = 2 + (NrIntfs \times (1 + X))\\ $$" /></a>
bytes. Thus the total size of the extension field in
bytes is bounded from above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(Len&space;\times&space;2)&space;&plus;&space;(&space;(\sum_1^{Len}&space;NrIntfs_i)&space;\times&space;(1&space;&plus;&space;1))&space;\\&space;=&space;3&space;&plus;&space;(2&space;\times&space;Len)&space;&plus;&space;(&space;(1&space;&plus;&space;1)&space;\times&space;TotIntfs)&space;\\&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(Len&space;\times&space;2)&space;&plus;&space;(&space;(\sum_1^{Len}&space;NrIntfs_i)&space;\times&space;(1&space;&plus;&space;1))&space;\\&space;=&space;3&space;&plus;&space;(2&space;\times&space;Len)&space;&plus;&space;(&space;(1&space;&plus;&space;1)&space;\times&space;TotIntfs)&space;\\&space;$$" title="$$ Size[Ext] = Size[ST] + Size[Len] + Size[BR_1] + ... + Size[BR_n] \\ \leq 1 + 2 + (Len \times 2) + ( (\sum_1^{Len} NrIntfs_i) \times (1 + 1)) \\ = 3 + (2 \times Len) + ( (1 + 1) \times TotIntfs) \\ $$" /></a>
Where Len is equivalent to the number of BRs deployed by the AS and TotIntfs
is the total number of all interfaces attached to any of the BRs.

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

The following diagram shows the structure of the payload for this extension.
<a href="https://www.codecogs.com/eqnedit.php?latex=$BWI&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;...&space;\|&space;BR_n&space;\rangle$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$BWI&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;...&space;\|&space;BR_n&space;\rangle$" title="$BWI = \langle ST \| Len \| BR_1 \| ... \| BR_n \rangle$" /></a>
It starts with the
subtype field, which has a length of 1 byte and for Maximum Bandwidth
Information will be set to 4, i.e. 00000100. Next is the Len field, which is
2 bytes long and denotes the number of BRs in the AS the current AS Entry is
referring to. Now follow a total of Len BR_i-fields. Each BR_i field is
itself divided into parts as shown below: <a href="https://www.codecogs.com/eqnedit.php?latex=$BR_i&space;=&space;\langle&space;MaxBW&space;\|&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;IntfBW_1&space;\|&space;...&space;\|&space;IntfID_n&space;\|&space;IntfBW_n&space;\rangle$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$BR_i&space;=&space;\langle&space;MaxBW&space;\|&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;IntfBW_1&space;\|&space;...&space;\|&space;IntfID_n&space;\|&space;IntfBW_n&space;\rangle$" title="$BR_i = \langle MaxBW \| NrIntfs \| IntfID_1 \| IntfBW_1 \| ... \| IntfID_n \| IntfBW_n \rangle$" /></a>
The MaxBW field
contains a 32-bit uint that describes the minimum across the maximum bandwidths
of all links on the path between the egress interface and BR_i (this value is
set to zero for the case where BR_i is the same BR that the egress interface
is attached to), in terms of bits per second. The NrIntfs field is 1 byte long
and is to be interpreted as an unsigned integer that describes the number of
interfaces attached to BR_i. The IntfID_i fields encode the interface ID in
1 byte. Each IntfBW_i field denotes a 32 bit uint, which refers to the
maximum bandwidth of the link attached to this interface in bits per second. To
summarize, the space required by the Maximum Bandwidth Information extension in
bytes is calculated as the sum of the amount of space consumed by the ST, the
Len field and  the Len BR_i fields. The size of each BR_i field can be
bounded from above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[BR_i]&space;=&space;Size[MaxBW]&space;&plus;&space;Size[NrIntfs]&space;&plus;&space;Size[Intf_1]&space;&plus;&space;...&space;&plus;&space;Size[Intf_n]&space;\\&space;\leq&space;4&space;&plus;&space;1&space;&plus;&space;4&space;&plus;&space;1&space;&plus;&space;...&space;&plus;&space;4&space;&plus;&space;1&space;=&space;5&space;&plus;&space;(NrIntfs&space;\times&space;(4&space;&plus;1))&space;\\&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[BR_i]&space;=&space;Size[MaxBW]&space;&plus;&space;Size[NrIntfs]&space;&plus;&space;Size[Intf_1]&space;&plus;&space;...&space;&plus;&space;Size[Intf_n]&space;\\&space;\leq&space;4&space;&plus;&space;1&space;&plus;&space;4&space;&plus;&space;1&space;&plus;&space;...&space;&plus;&space;4&space;&plus;&space;1&space;=&space;5&space;&plus;&space;(NrIntfs&space;\times&space;(4&space;&plus;1))&space;\\&space;$$" title="$$ Size[BR_i] = Size[MaxBW] + Size[NrIntfs] + Size[Intf_1] + ... + Size[Intf_n] \\ \leq 4 + 1 + 4 + 1 + ... + 4 + 1 = 5 + (NrIntfs \times (4 +1)) \\ $$" /></a>
bytes. Thus the total size of the extension field in bytes is bounded from
above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(Len&space;\times&space;5)&space;&plus;&space;(&space;(\sum_1^{Len}&space;NrIntfs_i)&space;\times&space;(4&space;&plus;&space;1))&space;\\&space;=&space;3&space;&plus;&space;(5&space;\times&space;Len)&space;&plus;&space;(&space;(4&space;&plus;&space;1)&space;\times&space;TotIntfs)&space;\\&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(Len&space;\times&space;5)&space;&plus;&space;(&space;(\sum_1^{Len}&space;NrIntfs_i)&space;\times&space;(4&space;&plus;&space;1))&space;\\&space;=&space;3&space;&plus;&space;(5&space;\times&space;Len)&space;&plus;&space;(&space;(4&space;&plus;&space;1)&space;\times&space;TotIntfs)&space;\\&space;$$" title="$$ Size[Ext] = Size[ST] + Size[Len] + Size[BR_1] + ... + Size[BR_n] \\ \leq 1 + 2 + (Len \times 5) + ( (\sum_1^{Len} NrIntfs_i) \times (4 + 1)) \\ = 3 + (5 \times Len) + ( (4 + 1) \times TotIntfs) \\ $$" /></a>
Where Len is equivalent to the number of BRs deployed by the AS and TotIntfs
is the total number of all interfaces attached to any of the BRs.

### Number of Internal Hops

#### Definition Number of Internal Hops

The Number of Internal Hops is defined as follows:
> The Number of Internal Hops describes how many hops are on the Intra-AS path.

#### Use Cases

- Can be used to exclude undesireable paths from the selection
- Obtain a selection of efficient, low latency paths (especially when combined
  with Latency Information)

#### Conceptual Implementation

The following diagram shows the structure of the payload for this extension.
<a href="https://www.codecogs.com/eqnedit.php?latex=NIH&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;BR_2&space;\|&space;...&space;\|&space;BR_n&space;\rangle" target="_blank"><img src="https://latex.codecogs.com/svg.latex?NIH&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;BR_1&space;\|&space;BR_2&space;\|&space;...&space;\|&space;BR_n&space;\rangle" title="NIH = \langle ST \| Len \| BR_1 \| BR_2 \| ... \| BR_n \rangle" /></a>
It starts with
the subtype field, which has a length of 1 byte and for Number of Internal Hops
will be set to 5, i.e. 00000101. Next is the Len field, which is 2 bytes long and denotes the number of
BRs in the AS the ASE is referring to. Now follow a total of Len BR-fields.
Each BR_i field is itself divided into parts as shown below:
<a href="https://www.codecogs.com/eqnedit.php?latex=BR_i&space;=&space;\langle&space;Hops&space;\|&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;...&space;\|&space;IntfID_n&space;\|&space;\rangle" target="_blank"><img src="https://latex.codecogs.com/svg.latex?BR_i&space;=&space;\langle&space;Hops&space;\|&space;NrIntfs&space;\|&space;IntfID_1&space;\|&space;...&space;\|&space;IntfID_n&space;\|&space;\rangle" title="BR_i = \langle Hops \| NrIntfs \| IntfID_1 \| ... \| IntfID_n \| \rangle" /></a>
Here, Hops denotes
a uint of size 1 byte, which refers to the number of hops between the egress
interface and any interface attached to BR_i (this value is set to zero for
the case where BR_i is the egress BR). NrIntfs refers to the number of
interfaces attached to this BR, expressed as a 2 byte long uint . IntfID_i
encodes the interface ID in 1 byte. To summarize, the space required by the
Number of Internal Hops extension in bytes is calculated as the sum of the
amount of space consumed by the ST, the Len field and the Len BR_i
fields. Thus the total size of the extension field in bytes is bounded from
above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(2&space;\times&space;Len)&space;&plus;&space;(X&space;\times&space;TotIntfs)&space;\\&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[BR_1]&space;&plus;&space;...&space;&plus;&space;Size[BR_n]&space;\\&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;(2&space;\times&space;Len)&space;&plus;&space;(X&space;\times&space;TotIntfs)&space;\\&space;$$" title="$$ Size[Ext] = Size[ST] + Size[Len] + Size[BR_1] + ... + Size[BR_n] \\ \leq 1 + 2 + (2 \times Len) + (X \times TotIntfs) \\ $$" /></a>
Where Len is equivalent to the number of BRs deployed by the AS, and TotIntfs
is the total number of interfaces attached to any of the BRs.

### Note

#### Definition Note

The Note is defined as follows:
> A bit of plaintext in the form of an ASCII character string.

#### Use Cases Note

- Tool for network engineers to communicate interesting/important information to
  their peers as well as users

#### Conceptual Implementation Note

The following diagram shows the structure of the payload for this extension. $NI
= \langle ST \| Len \| Notes \rangle$ It starts with the subtype field, which
has a length of 1 byte and for Note will be set to 6, i.e. 00000110. Next is
the Len field, which is 2 bytes long and denotes the number of BRs in the AS
the ASE is referring to. Now follows a Notes field, which represents a string
of ASCII characters, each of which is encoded within 1 byte. The maximum number
of characters is set to 997. To summarize, the space required by the Notes
extension in bytes is calculated as the sum of the amount of space consumed by
the ST field, the Len field and the Notes field. Thus the total size of
the extension field in bytes is bounded from above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[Notes]&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;997&space;=&space;1000&space;\\&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[Notes]&space;\leq&space;1&space;&plus;&space;2&space;&plus;&space;997&space;=&space;1000&space;\\&space;$$" title="$$ Size[Ext] = Size[ST] + Size[Len] + Size[Notes] \leq 1 + 2 + 997 = 1000 \\ $$" /></a>

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

The following diagram shows the structure of the payload for this extension.
<a href="https://www.codecogs.com/eqnedit.php?latex=$MEI&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;URL&space;\rangle$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$MEI&space;=&space;\langle&space;ST&space;\|&space;Len&space;\|&space;URL&space;\rangle$" title="$MEI = \langle ST \| Len \| URL \rangle$" /></a>
It starts with the subtype field, which
has a length of 1 byte and for Metadata endpoint will be set to 7, i.e.
00000111. Next is the $Len$ field, which is 1 byte long and denotes the number
of characters in the URL. Now follows a URL field, which represents a string
of ASCII characters, each of which is encoded within 1 byte. The maximum number
of characters is set to 98. To summarize, the space required by the Notes
extension in bytes is calculated as the sum of the amount of space consumed by
the ST field, the Len field and the URL field. Thus the total size of the
extension field in bytes is bounded from above by
<a href="https://www.codecogs.com/eqnedit.php?latex=$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[URL]&space;\leq&space;1&space;&plus;&space;1&space;&plus;&space;98&space;=&space;100&space;\\&space;$$" target="_blank"><img src="https://latex.codecogs.com/svg.latex?$$&space;Size[Ext]&space;=&space;Size[ST]&space;&plus;&space;Size[Len]&space;&plus;&space;Size[URL]&space;\leq&space;1&space;&plus;&space;1&space;&plus;&space;98&space;=&space;100&space;\\&space;$$" title="$$ Size[Ext] = Size[ST] + Size[Len] + Size[URL] \leq 1 + 1 + 98 = 100 \\ $$" /></a>

## Concrete Implementation

The following section is devoted to looking at the implementation of each
property in detail.

### General Approach

Asdf.
