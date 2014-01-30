We have implemented the below functionalities

1. The router correctly handles ARP requests and replies.
2. The router responds correctly to ICMP echo requests.
3. The router correctly handles traceroutes through it (where it is not the end host) and to it (where it is the end host).
4. The router can successfully route packets between the gateway and the application servers.
5. The router maintains an ARP cache whose entries are invalidated after a timeout period (timeouts should be on the order of 15 seconds).
6. The router does not needlessly drop packets (for example when waiting for an ARP reply)
7. The router handles tcp/udp packets sent to one of its interfaces. In this case the router should respond with an ICMP port unreachable.
8. The router enforces guarantees on timeouts.

