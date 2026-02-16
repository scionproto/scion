//go:build linux

// afxdptest is a minimal program that attaches an XDP program and opens an
// AF_XDP socket — exercising the same code path as the router's afxdpudpip
// underlay provider. Run as root (or with CAP_NET_ADMIN + CAP_BPF).
//
// Usage:
//
//	afxdptest [--mtu 3400] [--iface veth_test]             # creates veth pair
//	afxdptest --no-create --iface <existing-interface>      # uses existing interface
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/scionproto/scion/private/underlay/afxdp"
)

func main() {
	mtu := flag.Int("mtu", 3400, "MTU for the veth pair")
	ifName := flag.String("iface", "veth_xdp0", "container-side veth name")
	noCreate := flag.Bool("no-create", false, "skip veth creation, use existing interface")
	flag.Parse()

	if err := run(*ifName, *mtu, *noCreate); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK: AF_XDP socket opened and closed successfully")
}

func run(ifName string, mtu int, noCreate bool) error {
	if !noCreate {
		peerName := ifName + "_peer"
		// Clean up any leftover from a previous run.
		_ = sh("ip", "link", "del", ifName)

		// Create veth pair.
		fmt.Printf("Creating veth pair %s <-> %s (mtu %d)...\n", ifName, peerName, mtu)
		if err := sh("ip", "link", "add", ifName, "mtu", fmt.Sprint(mtu),
			"type", "veth", "peer", "name", peerName, "mtu", fmt.Sprint(mtu)); err != nil {
			return fmt.Errorf("creating veth pair: %w", err)
		}
		defer sh("ip", "link", "del", ifName) //nolint:errcheck

		if err := sh("ip", "addr", "add", "10.99.0.1/24", "dev", ifName); err != nil {
			return fmt.Errorf("adding address: %w", err)
		}
		if err := sh("ip", "link", "set", ifName, "up"); err != nil {
			return fmt.Errorf("setting link up: %w", err)
		}
		if err := sh("ip", "link", "set", peerName, "up"); err != nil {
			return fmt.Errorf("setting peer up: %w", err)
		}
	}

	// Resolve the interface.
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("interface lookup: %w", err)
	}
	fmt.Printf("Interface %s index=%d mtu=%d\n", iface.Name, iface.Index, iface.MTU)

	// Step 1: Attach XDP program.
	fmt.Println("Attaching XDP program...")
	xdpIface, err := afxdp.NewInterface(ifName)
	if err != nil {
		return fmt.Errorf("NewInterface: %w", err)
	}
	defer xdpIface.Close()
	fmt.Println("  XDP program attached.")

	// Step 2: Open AF_XDP socket (copy mode, queue 0).
	fmt.Println("Opening AF_XDP socket (copy mode, queue 0)...")
	conf := afxdp.SocketConfig{QueueID: 0}
	sock, err := afxdp.Open(conf, xdpIface, false, false)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer sock.Close()
	fmt.Printf("  AF_XDP socket opened (zerocopy=%v, hugepages=%v)\n",
		sock.IsZerocopy(), sock.IsHugepages())

	return nil
}

func sh(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
