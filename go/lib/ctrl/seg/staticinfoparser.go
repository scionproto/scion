package seg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Latpair2 struct {
	IntfId uint16 `json:"ID"`
	Delay  uint16 `json:"Delay"`
}

type Latintf struct {
	IntfId uint16     `json:"ID"`
	Peer   bool       `json:"Peer"`
	Inter  uint16     `json:"Inter"`
	Intra  []Latpair2 `json:"Intra"`
}

type BWpair2 struct {
	IntfId  uint16 `json:"ID"`
	BWintra uint32 `json:"BW"`
}

type Bwintf struct {
	IntfId uint16    `json:"ID"`
	Peer   bool      `json:"Peer"`
	Inter  uint32    `json:"Inter"`
	Intra  []BWpair2 `json:"Intra"`
}

type LTpair2 struct {
	IntfId uint16 `json:"ID"`
	LT     string `json:"LT"`
}

type LTintf struct {
	IntfId uint16    `json:"ID"`
	Peer   bool      `json:"Peer"`
	Inter  string    `json:"Inter"`
	Intra  []LTpair2 `json:"Intra"`
}

type Geointf struct {
	ID      uint16  `json:"ID"`
	Peer    bool    `json:"Peer"`
	C1      float32 `json:"C1"`
	C2      float32 `json:"C2"`
	CivAddr []byte  `json:"CivAddr"`
}

type Hoppair2 struct {
	IntfId uint16 `json:"ID"`
	HN     uint8  `json:"HN"`
}

type Hopintf struct {
	IntfId uint16     `json:"ID"`
	Peer   bool       `json:"Peer"`
	Intra  []Hoppair2 `json:"Intra"`
}

type specnote struct {
	IntfId uint16 `json:"ID"`
	Msg    string `json:"Msg"`
}

type Note2 struct {
	Default  string     `json:"Default"`
	Specific []specnote `json:"Specific"`
}

type MI2 struct {
	Lat  []Latintf `json:"Latency"`
	BW   []Bwintf  `json:"Bandwidth"`
	LT   []LTintf  `json:"Linktype"`
	Geo  []Geointf `json:"Geo"`
	Hops []Hopintf `json:"Hops"`
	N    Note2     `json:"Note"`
}

type MarshalInterfaces struct {
	NPIs []Unmarshalingstructlvl2 `json:"NonPeeringInterfaces"`
	PIs  []Unmarshalingstructlvl2 `json:"PeeringInterfaces"`
}

type Unmarshalingstructlvl1 struct {
	Interfaces  MarshalInterfaces `json:"Interfaces"`
	DefaultNote string            `json:"DefaultNote"`
}

type Unmarshalingstructlvl2 struct {
	HiddenID     int
	IntfID       uint64   `json:"IntfID"`
	IntraLatency []uint16 `json:"IntraLatency"`
	InterLatency uint16   `json:"InterLatency"`
	C1           float32  `json:"C1"`
	C2           float32  `json:"C2"`
	CivAddr      []byte   `json:"CivAddr"`
	IntraLink    []string `json:"IntraLink"`
	InterLink    string   `json:"InterLink"`
	IntraBW      []uint32 `json:"IntraBW"`
	InterBW      uint32   `json:"InterBW"`
	SpecificNote string   `json:"SpecificNote"`
	Hops         []uint8  `json:"Hops"`
}

type EgressIntf struct {
	Egint       uint64
	HiddenEgint int
}

type egress interface {
	sethiddenegint(Unmarshalingstructlvl1)
}

func (trueegint *EgressIntf) sethiddenegint(somestruct Unmarshalingstructlvl1) {
	for i := 0; i < len(somestruct.Interfaces.NPIs); i++ {
		if somestruct.Interfaces.NPIs[i].IntfID == trueegint.Egint {
			trueegint.HiddenEgint = i
		}
	}
	for i := 0; i < len(somestruct.Interfaces.PIs); i++ {
		if somestruct.Interfaces.PIs[i].IntfID == trueegint.Egint {
			trueegint.HiddenEgint = i + len(somestruct.Interfaces.NPIs)
		}
	}
}

func parsenewlvl1(somefile string) MI2 {
	jsonFile, err := os.Open(somefile)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	fmt.Print("Opened file: ", somefile, "\n")
	rawfile, _ := ioutil.ReadAll(jsonFile)
	//fmt.Print("Printing rawfile: ", rawfile, "\nRawfile OVER\n")
	var res MI2
	json.Unmarshal(rawfile, &res)
	//fmt.Print("parselvl1 check: peer ", res.Peer, " nonpeer ", res.Nonpeer, " N ", res.N, " Defaultnote ", res.DefaultNote, "\n")
	//fmt.Print("parselvl1 interfaces: ", res.Interfaces.NPIs, res.Interfaces.PIs, "\n")
	return res
}

func parsenew(somefile string, egint uint16, inIFID uint16) StaticInfoExtn {
	var somedata = parsenewlvl1(somefile)
	var res StaticInfoExtn
	res.LI.lc2(somedata, egint, inIFID)
	res.BW.bwc2(somedata, egint, inIFID)
	res.LT.ltc2(somedata, egint, inIFID)
	res.GI.gc2(somedata, egint)
	res.NI.na2(somedata, egint)
	res.IH.nhc2(somedata, egint, inIFID)
	return res
}
