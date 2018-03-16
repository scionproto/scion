// Note:
//
// This temporary file is included as a proof of concept. It will not be pushed
// to the upstream repository.

package main

import (
	"fmt"
	"os"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("error: ", err)
	}
	fmt.Print(dir)
}
