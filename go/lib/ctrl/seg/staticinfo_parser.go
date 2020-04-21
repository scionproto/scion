package seg

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/proto"
  
  "encoding/json"
	"io/ioutil"
	"os"
	"math"
	"strconv"
)


type Latintf struct {
	Inter  uint16     `json:"Inter"`
	Intra  map[uint16]uint16 `json:"Intra"`
}

type Bwintf struct {
	Inter  uint32    `json:"Inter"`
	Intra  map[uint16]uint32 `json:"Intra"`
}

type Geointf struct {
	Longitude      float32 `json:"Longitude"`
	Latitude      float32 `json:"Latitude"`
	Address string  `json:"Address"`
}

type Hopintf struct {
	Intra  map[uint16]uint8 `json:"Intra"`
}

type MI2 struct {
	Lat  map[uint16]Latintf `json:"Latency"`
	BW   map[uint16]Bwintf  `json:"Bandwidth"`
	LT   map[uint16]string  `json:"Linktype"`
	Geo  map[uint16]Geointf `json:"Geo"`
	Hops map[uint16]Hopintf `json:"Hops"`
	N    string             `json:"Note"`
}


func parsenewlvl1(datafile string, topologyfile string) (MI2, map[uint16]bool) {
	jsonFile, err := os.Open(datafile)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	rawfile, _ := ioutil.ReadAll(jsonFile)
	var res MI2
	json.Unmarshal(rawfile, &res)
	var temp Topo
	peers := make(map[uint16]bool)
	topologyjson, err := os.Open(topologyfile)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	topologyraw,_ := ioutil.ReadAll(topologyjson)
	json.Unmarshal(topologyraw, &temp)
	for _,BR := range temp.BRs{
		for intf, val := range BR.Intfs{
			peers[intf] = (val.LinkTo == "PEER")
		}
	}
	return res, peers
}

func generateStaticinfo(datafile string, topologyfile string, egint uint16, inIFID uint16) *StaticInfoExtn {
	var somedata, peers = parsenewlvl1(datafile, topologyfile)
	var res StaticInfoExtn
	res.LI.gatherlatency(somedata, peers, egint, inIFID)
	res.BW.gatherbw(somedata, peers, egint, inIFID)
	res.LT.gatherlinktype(somedata,peers, egint)
	res.GI.gathergeo(somedata)
	res.NI = somedata.N
	res.IH.gatherhops(somedata, egint, inIFID)
	return &res
}
