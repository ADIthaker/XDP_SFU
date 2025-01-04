# Implementing SFU in XDP

## Overview

This project explores implementing a Selective Forwarding Unit (SFU) for video conferencing using **XDP (eXpress Data Path)** and **Traffic Control (TC)** in the Linux kernel. By leveraging **eBPF (Extended Berkeley Packet Filter)** technology, the project aims to enhance the performance of packet processing by bypassing the traditional Linux networking stack.

## Motivation

- **Video Conferencing Challenges**:  
  SFU servers process and forward media streams, but they face inefficiencies due to the need to traverse the entire Linux stack.
- **eBPF Advantages**:  
  eBPF programs can run at the driver level, improving packet processing speed.
- **Goals**:  
  - Enable forwarding packets with flexibility in quality and format.  
  - Optimize performance for multi-participant video conferencing.  

## About XDP and TC

- **XDP**:  
  A high-performance framework for packet processing at the link layer.  
  - **Advantages**: Fast and efficient.  
  - **Limitations**: Limited memory and restricted packet access.
  
- **TC**:  
  Operates within the Linux network stack, allowing full packet modification.  
  - **Advantages**: Packet cloning and extended manipulation capabilities.  
  - **Limitations**: Slower than XDP.

## About SFU

An SFU is a specialized network architecture for video conferencing that:  
- Receives all participant streams.  
- Processes and forwards streams based on participants' needs.  
- Utilizes RTP (Real-time Transport Protocol) for media streams and control packets (e.g., SDP, RTCP, ICE).

## Progress

- Implemented SFU for 2 participants using XDP and TC.
- eBPF maps used to store participant IPs and ports.
- Scapy scripts created to generate RTP packets for testing.
- Utilized tools for debugging and analysis:
  - `bpf_printk` for tracing.
  - `llvm-objdump` for compiler inspection.
  - `tcpdump` and `xdpdump` for packet monitoring.
  - `bpftool` for map visualization.

## Challenges

- **XDP Limitations**:  
  - Restricted stack memory (512 bytes).  
  - Single packet in/out framework.  
- **TC Limitations**:  
  - Slower than XDP.  
- **Documentation Gaps**:  
  - Sparse resources for pointer arithmetic and data types.  
- **Control Plane Integration**:  
  - Requires application-layer modifications via AF_XDP sockets.  
- **Debugging**:  
  - Minimal support for meaningful debug outputs.

## Resources

1. [Supercharge WebRTC with eBPF/XDP (T. Lévai et al., 2023)](https://doi.org/10.1145/3609021.3609296)
2. [XDP Project - Tutorials](https://github.com/xdp-project/xdp-tutorial)
3. [Debugging XDP Packet Issues](https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it)
4. [WebRTC for the Curious](https://webrtcforthecurious.com)

## Setup dependencies

Before you can start completing step in this tutorial, you will need to
install a few dependencies on your system. These are described in
[setup](./setup_dependencies.org).
### Runnning the programs

 - XDP:
    ```
    # /sfu/sfu
    make
    ./xdp-loader load -m skb lo xdp_prog_kern.o -p /sys/fs/bpf/lo -vv   # load bpf with pin path to map to loopback
    ./xdp-loader unload lo --all                                        # unload program
    ./xdp-loader clean lo                                               # clean all links


    # Debugging/Outpu

    xdpdump -i lo --rx-capture exit
    cat /sys/kernel/debug/tracing/trace-pipe

    ```
 - TC:
    ```
    # /sfu/sfu
    clang -O2 -emit-llvm -g -c tc_prog_kern.c -o- | llc -march=bpf -mcpu=probe -filetype=obj tc_prog_kern.o

    tc qdisc add dev lo clsact                               # create a qdisc
    tc filter add dev lo ingress bpf da obj tc_prog_kern.o   # load bpf 
    tc qdisc del dev lo clsact                               # remove bpf chain

    # Debugging/Output

    tcpdump -i lo 
    cat /sys/kernel/debug/tracing/trace-pipe

    ```
