## SCION IP Gateway

Current version is a barebone proof of concept for the SIG.

### Host configuration

Enable routing:

```
  sudo sysctl -w net.ipv4.ip_forward=1
```

Disable Reverse Path Filtering:

```
  sudo sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
```

### Testing

Run the SIG as root:

```
sudo sig -config sig.config -sciond /run/shm/sciond/sd1-14.sock -dispatcher /run/shm/dispatcher/default.sock -isdas 1-14 -encapip 169.254.1.2 -encapport 10080 -ctrlport 10081
```

Argument `-cli` can be used to enable the optional interactive console.

### Management

#### Interactive console

List of supported commands:
```
Commands:
  clear                 clear the screen
  exit                  exit the program
  help                  display help
  show.route            show.route
  static.route.add      static.route.add <ipv4-subnet> <isdas>
  static.route.del      static.route.del <ipv4-subnet> <isdas>
  static.sig.add        static.sig.add <isdas> <encap-ip> <encap-port> <ctrl-ip> <ctrl-port>
  static.sig.del        static.sig.del <isdas> <encap-ip> <encap-port> <ctrl-ip> <ctrl-port>
```

#### Config files
Config files can be loaded at startup with `-config`. They contain SIG Console commands, one per line.

Config file example:

```
# ETH-Test config file with two SIGs on remote AS 1-10

static.sig.add 1-10 198.51.100.1 10080 198.51.100.1 10080
static.sig.add 1-10 198.51.100.2 10080 198.51.100.2 10080
static.route.add 203.0.113.0/24 1-10
```

### Features and roadmap

Current status:
* Control plane:
  * Static only (using interactive console or config files)
  * Can register multiple SIGs for each remote AS
  * Can register multiple prefixes for each remote AS
  * SIG-SIG transport protocol
* Data plane:
  * Encapsulation/decapsulation is done in user space
  * No load balancing logic
  * IPv4 only

TODOs:
* Control plane:
  * SIG-SIG Keepalive protocol
* Data plane:
  * IPv6 support


#### Dev notes

### General design
SIGs listen to incoming traffic from other SIGs on UDP port 10080.

When a new SIG for a remote AS is registered, a TUN interface named `scion.<ISD-AS>` is created on the host Linux machine. When a new prefix is added for that AS, a route is injected in the main Linux routing table which redirects traffic to the corresponding tunnel interface. The SIG reads all data on the interface and encapsulates each packet, reinserting it in the main routing process through a scion.local TUN interface.

No lookups are needed in the data plane, because the routing has already been performed by the Linux routing table.

### Data structures
**SIG Table**. (defined in `base/sdb.go`) This is the main data structure of the SIG and is a thread-safe hashtable of information on remote ASes. Specifically, for each AS (defined in `base/asinfo.go`), the following information is stored:
  * Map of IPv4 prefixes assigned to the AS
  * Map of SIGs, containing encap IP, encap Port, control IP, and control Port
  * Tunnel device through which the local kernel can send traffic to the AS

SIG table methods can be used by various data sources (currently only static, but IAC lookups and SIG lookups might be implemented in the future) to:
  * Add/delete a prefix for a remote AS
  * Add/delete a SIG for a remote AS

Adding the first SIG for a remote AS automatically creates the information structure for that AS, together with its tunnel interface (e.g., `scion.100-1`). Additionally, a new EgressWorker is created that takes the IP traffic from the tunnel interface, encapsulates it into SIG-SIG frames, and then encapsulates it into a SCION/UDP packet and sends it to the remote SIG using UDP. For each added SIG, a `*SCIONConn` object which supports reads ands writes is initialized from the local SCION Context (detailed in the following paragraph). Adding routes to the AS then injects routes in the Linux kernel.

**Context**. (defined in `lib/scion/scion.go`) The SCION Context structure represents the local information needed to populate a SCION packet. It contains references to the dispatcher, SCIOND and the local ISDAS. The Context has methods to `Dial` to a remote SCION host or `Listen` on a local SCION/UDP port. Both methods return `*SCIONConn` objects which implement `net.Conn` and `net.PacketConn`. Reads and writes to `*SCIONConn` structures operate similarly to UDP, except local addresses and remote addresses are a (ISDAS, IPv4, UDP port) tuple.

Writing to `*SCIONConn` requires a valid path. `*SCIONConn` contains an reference to a `PathManager` (defined in `lib/scion/paths.go`) which is queried on demand whenever a Write is performed. The `PathManager` is tied to the SCION Context, so all SCION connections created from the same context share the same Path cache.

### Egress traffic
(Goes from IP network to SCION network, functions defined in `forward.go`)

Traffic goes through the Linux routing table which contains injected routes towards a `scion.<ISD-AS>` L3 tunnel interface. The data is taken from the tunnel by the `asyncReader` function, which sends it to a buffer. Another function, `EgressWorker` takes data from the buffer and sends it via a `*SCIONConn.Write` to a remote SIG. The connection for the remote SIG is chosen for each packet by invoking `getConn()` on the destination AS. Retrieving the connection handle on each packet makes it possible for control plane modules to change the list of active SIGs (e.g., on failover) without the data plane being impacted.

### Ingress
(Goes from SCION network to IP network, `IngressWorker` defined in `forward.go`)

Before starting the ingress receiver, the parent goroutine calls `ListenSCION` to start listening for any SCION packets on a SCION/UDP port (typically 10080), and receives a `*SCIONConn` structure (`ExternalIngress`). Additionally, it creates a new tunnel interface (`scion.local`) which can be used to inject packets in the Linux routing process.

Each SIG contains a single `IngressWorker` goroutine, spawned at program start. The `IngressWorker` then reads SIG-SIG frames from the `ExternalIngress` port, decapsulates the outer SCION header and processes the IP packets within. Once an IP packet has been successfully reassembled, it is sent to the `scion.local` tunnel interface.

Notes on Ingress limitations:
  * The SIG contains only one receive state (one reassembly buffer, one frame sequence number); this breaks whenever more than one remote SIG is sending traffic and needs to be fixed in a future version
  * If a frame with a sequence number that is in the past arrives, it is discarded
  * If a frame with a sequence number that is not the expected sequence number arrives, any packet that is still pending reassembly is discarded (since at this point it is corrupted)

### Information sources

The SIG currently only supports static configuration (defined in `control/static.go`). Methods called on a Static information source by the management interface simply get passed on to the main SCION table.

Other information sources (e.g., dynamic IACs) might get added in the future. These will probably operate as separate goroutines that also call methods on the main SCION table to add/delete remote SIGs and prefixes. Dynamic sources will also be configured by loading configs through the Management interface.

### Management

The main goroutine concludes by processing a config file (if that exists), and then starting an interactive console (if the runtime flag has been enabled). The console has hooks for various Information sources (currently only `Static` is available).

### Files
  * Data structures:
    * `asinfo.go` - information for each remote AS
    * `sdb.go` - main SIG table, hashtable of all known remote ASes, exposes methods to information sources (e.g., Static config)
  * Networking:
    * `lib/scion/scion.go` - contains `*SCIONConn`, a type which implements `net.Conn` and `net.PacketConn` for SCION traffic; also contains `Context`, which includes local information for SCION connections
    * `lib/scion/paths.go` - implements the local SCION paths cache as a separate goroutine
    * `lib/scion/addr.go` - contains `*SCIONAddr`, a type which implements `net.Addr` for complete SCION addresses
    * `xnet/xnet.go` - low level Linux networking middleware (e.g., netlink, tunneling)
  * Control sources:
    * `control/static.go` - just a proxy between management interfaces and the main SIG table
  * Data plane:
    *  `base/forward.go` - contains the goroutines for data traffic
  * Management interfaces:
    * `management/console.go` - implements the non-interactive console for loading configs and the interactive console for live management
  * `global/global.go` - global variables and flag parsing
  * `sig.go` main function
