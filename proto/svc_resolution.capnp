@0xa52f74a5947eb3b7;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

# An SVCResolutionReply must always fit within a UDP datagram. If the reply does not
# fit, there is no mechanism for clients and servers to establish control-plane
# reachability.
struct SVCResolutionReply {
    # Duplicate keys must be treated as errors.
    transports @0 :List(Transport);
}

struct Transport {
    # Protocol defined values:
    #   "QUIC"
    #   "UDP"
    # Unknown values should be ignored by clients.
    key @0: Text;
    # Protocol-specific server address descriptor.
    #
    # Supported formats for QUIC and UDP:
    #  192.168.0.1:80
    #  [2001:db8::1]:80
    # Missing ports / a port of 0 / invalid port values should be treated by
    # clients as errors.
    value @1: Text;
}
