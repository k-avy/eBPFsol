package main

import (
    "fmt"
    "os"
    "strconv"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

const (
    bpfFile  = "drop_tcp_port.o"
    mapName  = "port_map"
    progName = "drop_tcp_port"
    defaultPort = 4040
)

func main() {
    if len(os.Args) < 2 {
        fmt.Printf("Usage: %s <port>\n", os.Args[0])
        fmt.Printf("Using default port: %d\n", defaultPort)
    }

    port := defaultPort
    if len(os.Args) > 1 {
        var err error
        port, err = strconv.Atoi(os.Args[1])
        if err != nil {
            fmt.Printf("Invalid port number: %s\n", os.Args[1])
            return
        }
    }

    if err := rlimit.RemoveMemlock(); err != nil {
        fmt.Fprintf(os.Stderr, "failed to remove memlock: %v\n", err)
        os.Exit(1)
    }

    spec, err := ebpf.LoadCollectionSpec(bpfFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to load BPF spec: %v\n", err)
        os.Exit(1)
    }

    objs := struct {
        PortMap *ebpf.Map `ebpf:"port_map"`
        Program *ebpf.Program `ebpf:"drop_tcp_port"`
    }{}

    if err := spec.LoadAndAssign(&objs, nil); err != nil {
        fmt.Fprintf(os.Stderr, "failed to load BPF objects: %v\n", err)
        os.Exit(1)
    }
    defer objs.PortMap.Close()
    defer objs.Program.Close()

    var key uint32 = 0
    var value uint16 = uint16(port)
    if err := objs.PortMap.Put(key, value); err != nil {
        fmt.Fprintf(os.Stderr, "failed to update map: %v\n", err)
        os.Exit(1)
    }

    link, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.Program,
        Interface: 0,
    })
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to attach XDP program: %v\n", err)
        os.Exit(1)
    }
    defer link.Close()

    fmt.Printf("eBPF program loaded and attached. Dropping TCP packets on port %d\n", port)
    select {}
}
