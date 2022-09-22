# front panel port 9/0 ~ 17/0 
# -> server worker1~9
# -> device_port_id 56 48 40 32 24 16 8 0 4 (9 bit, for tofino & p4)

# use worker 6,7,8
bfrt.nat.ParserI.PORT_METADATA.add(16, 0)
bfrt.nat.ParserI.PORT_METADATA.add(8, 0)
bfrt.nat.ParserI.PORT_METADATA.add(0, 0)
bfrt.nat.IngressP.send_out.ip2port_mac.add_with_ipv4_forward(0xC0A80006, 32, 16, 0x0106, 0x0206)
bfrt.nat.IngressP.send_out.ip2port_mac.add_with_ipv4_forward(0xC0A80207, 32, 8, 0x0107, 0x0207)
