# eBPFsol

This repository contains a demonstration of an eBPF code to drop TCP packets on a specific port (default: 4040) with the capability to configure the port number from userspace.

## Setup

To use this code, you need to have the following prerequisites installed on your system:

* Linux kernel version 4.18 or later
* clang compiler version 9 or later
* libbpf library

You can install the prerequisites by following the instructions in the [eBPF documentation](https://ebpf.io/).

## Usage

1. Clone this repository to your local machine:

   ```shell
   git clone https://github.com/your-username/eBPFsol.git
   ```

2. Build the eBPF program:

   ```shell
   cd eBPFsol && cd cmd/ebpf
   ```

   ```shell
   go mod tidy
   go generate
   ```

   ``` shell
    go build .
   ```

3. Load the eBPF program:

   ```shell
    sudo go run . {port}
    ```

This script will load the eBPF program into the kernel.

4. Test the eBPF program:


   ```shell
    sudo tcpdump -i $INTERFACE_NAME$ port {port} 
    nc localhost {port}
   ```
   
Replace 'INTERFACE_NAME' with the interface on your machine.
Try connecting to the specified port (default: 4040) using `nc` or any other TCP client. The connection should be dropped by the eBPF program.
