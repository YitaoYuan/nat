this is a static-forward program work on L2.

to run this program,

first, you need a network "h1--(port0)sw(port1)--h2"

second, config ip address for veth on h1 & h2

third, make all links UP

fourth, use "route" to config static L3 forward on h1 & h2

fifth, use "arp" to config static ARP table on h1 & h2

sixth, use "simple_switch_CLI" on netns "sw" to add static forward entry in "eth_table", 
they are 
"(ingress_port = 0, DMAC = h2_veth_DMAC) => (egress_port = 1)"
"(ingress_port = 1, DMAC = h1_veth_DMAC) => (egress_port = 0)"

finally, you can ping h2 on h1, and vice versa

(if you delete any of the entry, ping will timeout)

