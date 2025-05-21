// Copyright 2018 Anapaya Systems
// Copyright 2025 SCION Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	topoFile  = flag.String("topoFile", "", "")
	graphFile = flag.String("graphFile", "", "")
	descName  = flag.String("descName", "", "")
	linksFile = flag.String("linksFile", "", "")
	ifIDsFile = flag.String("ifidsFile", "", "")
)

func main() {
	flag.Parse()
	switch {
	case *linksFile != "":
		writeLinksToFile()
	case *ifIDsFile != "":
		writeIfIDsToFile()
	default:
		writeGraphToFile()
	}
}

func writeLinksToFile() {
	err := WriteLinksToFile(*linksFile)
	if err != nil {
		fmt.Printf("Failed to write the links, err: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Printf("Successfully written the links to %s\n", *linksFile)
	}
}

func writeIfIDsToFile() {
	err := WriteIfIDsToFile(*topoFile, *ifIDsFile)
	if err != nil {
		fmt.Printf("Failed to write the ifIDs yaml file, err: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully written the ifIDs yaml to %s\n", *ifIDsFile)

func writeGraphToFile() {
	err := WriteGraphToFile(*topoFile, *graphFile, *descName)
	if err != nil {
		fmt.Printf("Failed to write the graph, err: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Printf("Successfully written graph to %s\n", *graphFile)
	}
}
