// Copyright 2019 Anapaya Systems
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

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/truststorage"
)

type Config struct {
	TrustDB truststorage.TrustDBConf
}

var (
	custDir = flag.String("customers", "", "The folder containing the customer keys")
	cfgFile = flag.String("config", "", "Configuration file containing the DB config.")

	config  Config
	trustDB trustdb.TrustDB
)

// TODO(lukedirtwalker): We probably need to initialize the logger here!
func main() {
	os.Exit(realMain())
}

func realMain() int {
	flag.Parse()
	if err := checkFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		flag.Usage()
		return 1
	}
	if err := loadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		flag.Usage()
		return 1
	}
	files, loadedCusts, err := LoadCustomers(*custDir, trustDB)
	printSummary(files, loadedCusts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during loading: %s\n", err)
		return 1
	}
	return 0
}

func checkFlags() error {
	if *custDir == "" {
		return common.NewBasicError("Missing custDir argument", nil)
	}
	if *cfgFile == "" {
		return common.NewBasicError("Missing config argument", nil)
	}
	return nil
}

func loadConfig() error {
	if _, err := toml.DecodeFile(*cfgFile, &config); err != nil {
		return common.NewBasicError("Failed to load config", err)
	}
	var err error
	trustDB, err = config.TrustDB.New()
	if err != nil {
		return common.NewBasicError("Failed to init the database", err)
	}
	return nil
}

func printSummary(files []string, loadedCusts []*CustKeyMeta) {
	fmt.Println("Successfully processed files:")
	for _, f := range files {
		fmt.Println(f)
	}
	fmt.Println("Successfully stored customers:")
	for _, cust := range loadedCusts {
		fmt.Printf("IA: %s, Version: %d\n", cust.IA, cust.Version)
	}
}
