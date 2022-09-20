# front panel port 9/0 ~ 17/0 
# -> server worker1~9
# -> device_port_id 56 48 40 32 24 16 8 0 4 (9 bit, for tofino & p4)

bfrt.nat.ParserI.PORT_METADATA.add(56, 40)
bfrt.nat.ParserI.PORT_METADATA.add(48, 40)
bfrt.nat.ParserI.PORT_METADATA.add(40, 40)
bfrt.nat.IngressP.send_out.ip2port_mac.add_with_ipv4_forward(0xC0A80001, 32, 56, 0x0101, 0x0201)
bfrt.nat.IngressP.send_out.ip2port_mac.add_with_ipv4_forward(0xC0A80202, 32, 48, 0x0102, 0x0202)
