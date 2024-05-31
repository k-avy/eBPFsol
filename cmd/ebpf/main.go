package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"os/signal"
)

const (
	// Default port to drop to
	defaultPort = 4040
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs drop_tcp_portObjects
	if err := loadDrop_tcp_portObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "lo" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach drop_tcp_packets to the network interface.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DropTcpPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdpLink.Close()

	log.Printf("Dropping TCP packets on port %d on %s..", defaultPort, ifname)

	// Update the port number in the drop_port map
	port := defaultPort
	if len(os.Args) > 1 {
		var portArg int
		if _, err := fmt.Sscanf(os.Args[1], "%d", &portArg); err == nil {
			port = portArg
		}
	}

	key := uint32(0)
	value := uint16(port)
	if err := objs.DropPort.Update(&key, &value, ebpf.UpdateAny); err != nil {
		log.Fatal("Updating drop_port map:", err)
	}

	log.Printf("Configured to drop TCP packets on port %d", port)

	// Periodically check for program interruption
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
    log.Print("Received signal, exiting..")
}