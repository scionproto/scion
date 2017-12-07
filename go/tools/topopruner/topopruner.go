package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/scionproto/scion/go/lib/topology"
)

var (
	infn   = flag.String("in", "", "Input file name. Required.")
	outfnf = flag.String("out", "", "Ouput file name for the full topology. Required.")
	outfnr = flag.String("reduced", "",
		"Ouput file name for the reduced topology. Defaults to not generating this output.")
	verbose = flag.Bool("verbose", false, "Be more verbose about what is going on")
)

func main() {
	flag.Parse()
	if *infn == "" || *outfnf == "" {
		fmt.Fprintf(os.Stderr,
			"You must specify an input file and an output file for the full topo.\n")
		os.Exit(-1)
	}
	rt, err := topology.LoadRawFromFile(*infn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input file: %s\n", err)
		os.Exit(-1)
	}
	finfo, err := os.Stat(*infn)
	if err != nil {
		// This should be pretty rare since the open() worked above
		fmt.Fprintf(os.Stderr, "Error stat()ing input file: %s\n", err)
		os.Exit(-1)
	}
	topology.StripBind(rt)
	marshalAndWriteOrDie(rt, *outfnf, "full", finfo.Mode())
	if *verbose {
		fmt.Printf("Wrote pruned full topo to '%s'.\n", *outfnf)
	}
	if *outfnr != "" {
		topology.StripServices(rt)
		marshalAndWriteOrDie(rt, *outfnr, "reduced", finfo.Mode())
		if *verbose {
			fmt.Printf("Wrote pruned reduced topo to '%s'.\n", *outfnr)
		}
	}
}

func marshalAndWriteOrDie(rt *topology.RawTopo, filename, ttype string, mode os.FileMode) {
	b, err := json.MarshalIndent(rt, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not marshal %s topo to JSON: %s\n", ttype, err)
		os.Exit(-1)
	}
	err = ioutil.WriteFile(filename, b, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not write out %s topo: %s\n", ttype, err)
		os.Exit(-1)
	}
}
