
### Setup dependencies

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
