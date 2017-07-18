package management

import (
	"bufio"
	"os"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/chzyer/readline"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/sig/control"
	"github.com/netsec-ethz/scion/go/sig/global"
)

func NewShell(static *control.StaticRP) *ishell.Shell {
	shell := ishell.New()

	shell.AddCmd(&ishell.Cmd{
		Name: "show.route",
		Help: "show.route",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 0 {
				c.Println("Error, usage: show.route")
				return
			}
			output := static.Print()
			c.Println(output)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "static.route.add",
		Help: "static.route.add <ipv4-subnet> <isdas>",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 2 {
				c.Println("Error, usage: static.route.add <ipv4-subnet> <isdas>")
				return
			}
			err := static.AddRoute(c.Args[0], c.Args[1])
			if err != nil {
				c.Println(err)
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "static.route.del",
		Help: "static.route.del <ipv4-subnet> <isdas>",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 2 {
				c.Println("Error, usage: static.route.del <ipv4-subnet> <isdas>")
				return
			}
			static.DelRoute(c.Args[0], c.Args[1])
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "static.sig.add",
		Help: "static.sig.add <isdas> <encap-ipv4-addr> <encap-port> <ctrl-ipv4-addr> <ctrl-port>",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 5 {
				c.Println("Error, usage: static.sig.add <isdas> <encap-ipv4-addr> <encap-port> <ctrl-ipv4-addr> <ctrl-port>")
				return
			}
			static.AddSig(c.Args[0], c.Args[1], c.Args[2], c.Args[3], c.Args[4])
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "static.sig.del",
		Help: "static.sig.del <isdas> <encap-ipv4-address> <encap-port>",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 3 {
				c.Println("Error, usage: static.sig.del <isdas> <encap-ipv4-addr> <encap-port>")
				return
			}
			static.DelSig(c.Args[0], c.Args[1], c.Args[2])
		},
	})
	return shell
}

func RunConfig(static *control.StaticRP, config string) {
	c := new(readline.Config)
	err := c.Init()
	if err != nil {
		log.Error("Unabled to initialize readline config", "err", err)
		return
	}

	f, err := os.Open(config)
	defer f.Close()

	c.Stdin = f
	if err != nil {
		log.Error("Unable to open config file", "filename", config)
		return
	}

	shell := NewShell(static)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		command := scanner.Text()
		log.Debug("Running command", "cmd", command)
		shell.Process(strings.Split(command, " ")...)
	}
	if err := scanner.Err(); err != nil {
		log.Error("Unable to read config file", "err", err)
	}
	log.Debug("Successfully loaded config", "filename", config)
}

func Run(static *control.StaticRP) {
	shell := NewShell(static)
	shell.Printf("SCION IP Gateway, version %v\n", global.Version)
	shell.Run()
}
