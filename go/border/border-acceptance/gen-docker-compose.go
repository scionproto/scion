// +build ignore

package main

import (
	//	"fmt"
	"os"
	"text/template"
)

const fileMode os.FileMode = 0664

func main() {
	fd, err := os.OpenFile("docker-compose.yml", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode)
	if err != nil {
		panic(err)
	}
	defer fd.Close()
	tmpl, err := template.ParseFiles("docker-compose.tmpl")
	if err != nil {
		panic(err)
	}
	info := struct {
		HostAddr string
		Network  string
		BorderID string
	}{
		"192.168.0.2",
		"192.168.0.0/24",
		"br1-ff00:0:1-2",
	}
	if err := tmpl.Execute(fd, info); err != nil {
		panic(err)
	}
}
