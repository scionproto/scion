package seg

type LatencyInfo struct {
	Egresslatency    uint16                  `capnp:"egressLatency"`
	Intooutlatency   uint16                  `capnp:"ingressToEgressLatency"`
	Childlatencies   []Latencychildpair      `capnp:"childLatencies"`
	Peeringlatencies []Latencypeeringtriplet `capnp:"peeringLatencies"`
}

type Latencychildpair struct {
	Intradelay uint16 `capnp:"intra"`
	Interface  uint16 `capnp:"ifID"`
}

type Latencypeeringtriplet struct {
	Interdelay uint16 `capnp:"inter"`
	IntraDelay uint16 `capnp:"intra"`
	IntfID     uint16 `capnp:"ifID"`
}

type BandwidthInfo struct {
	EgressBW  uint32   `capnp:"egressBW"`
	IntooutBW uint32   `capnp:"ingressToEgressBW"`
	BWPairs   []BWPair `capnp:"bandwidths"`
}

type BWPair struct {
	BW     uint32 `capnp:"bw"`
	IntfID uint16 `capnp:"ifID"`
}

type GeoInfo struct {
	Locations []Location `capnp:"locations"`
}

type Location struct {
	GPSData Coordinates `capnp:"gpsData"`
	IntfIDs []uint16    `capnp:"interfaces"`
}

type Coordinates struct {
	Latitude  float32 `capnp:"latitude"`
	Longitude float32 `capnp:"longitude"`
	Address   string  `capnp:"address"`
}

type LinktypeInfo struct {
	EgressLT     string          `capnp:"egressLinkType"`
	Peeringlinks []LTPeeringpair `capnp:"peeringLinks"`
}

type LTPeeringpair struct {
	IntfID uint16 `capnp:"ifID"`
	IntfLT string `capnp:"linkType"`
}

type InternalHopsInfo struct {
	Intououthops uint8     `capnp:"inToOutHops"`
	Hoppairs     []Hoppair `capnp:"interfaceHops"`
}

type Hoppair struct {
	Hops   uint8  `capnp:"hops"`
	IntfID uint16 `capnp:"ifID"`
}

type StaticInfoExtn struct {
	Latency   LatencyInfo      `capnp:"latency"`
	Geo       GeoInfo          `capnp:"geo"`
	Linktype  LinktypeInfo     `capnp:"linktype"`
	Bandwidth BandwidthInfo    `capnp:"bandwidth"`
	Hops      InternalHopsInfo `capnp:"internalHops"`
	Note      string           `capnp:"note"`
}
