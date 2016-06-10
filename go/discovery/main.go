package main

import (
	"flag"
	"time"

	"github.com/netsec-ethz/scion/go/zkutil"
	"github.com/samuel/go-zookeeper/zk"
)

func main() {
	flag.Parse()
	c, _, err := zk.Connect([]string{"127.0.0.1"}, time.Second) //*10)
	if err != nil {
		panic(err)
	}
	p := zkutil.NewParty(c, 1, 11, "sd1-11-2")
	err = p.Join()
	if err != nil {
		panic(err)
	}
}
