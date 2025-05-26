# What metrics do i keep track of?
There are a ton of metrics I could keep track of, but I need to start with a handful

1. Packets sent / recieved
  - tells you basic avtivity level of the machine
  - XDP or tc
2. Bytes sent / recieved
  - bandwidth usage, to identify large transfers or bottlenecks
  - XDP or tc (parse length of packets) (trivial)
3. Active TCP connections
  - how many connections are alive, spikes indicating scans, traffic bursts or service abuse
  - kprobe on tcp_set_state or sockops
4. Per-process bytes sent / recieved
  - which applications are using the network most, helps catch misbehaving processes
  - kprobe on tcp_sendmsg, tcp_recvmsg
5. TCP retransmissions
  - packet loss or poor network conditions
  - kprobe on tcp_retransmit_skb
6. DNS requests and responses
  - which domains are being queried. useful for identifying suspecious densitnations,
    malware activiy, or service dependencies
  - XDP or tc filtering UDP packets on port 53 and parsing payloads
7. Packet drops
  - whether the system or network stack is dropping packets
  - tracepoints on net:netif_receive_skb_drop skb:kfree_skb

