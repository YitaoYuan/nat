bfrt.nat.pipe.IngressParser.PORT_METADATA.add(180, 132, 0)
bfrt.nat.pipe.IngressParser.PORT_METADATA.add(164, 132, 0)
bfrt.nat.pipe.IngressParser.PORT_METADATA.add(148, 132, 1)
bfrt.nat.pipe.IngressParser.PORT_METADATA.add(132, 132, 2)

bfrt.nat.pipe.Ingress.send_out.l2_forward_table.add_with_l2_forward(0x1070fd190095, 180)
bfrt.nat.pipe.Ingress.send_out.l2_forward_table.add_with_l2_forward(0x1070fd2fd851, 164)
bfrt.nat.pipe.Ingress.send_out.l2_forward_table.add_with_l2_forward(0x1070fd2fe441, 148)
bfrt.nat.pipe.Ingress.send_out.l2_forward_table.add_with_l2_forward(0x1070fd2fd421, 132)

bfrt.nat.pipe.Ingress.send_out.l3_forward_table.add_with_l3_forward_in(0xC0A80101, 180, 0x020000000101, 0x1070fd190095)
bfrt.nat.pipe.Ingress.send_out.l3_forward_table.add_with_l3_forward_in(0xC0A80102, 164, 0x020000000101, 0x1070fd2fd851)
bfrt.nat.pipe.Ingress.send_out.l3_forward_table.add_with_l3_forward_out(0xC0A80203, 148, 0x020000000201, 0x1070fd2fe441)
bfrt.nat.pipe.Ingress.send_out.l3_forward_table.add_with_l3_forward_out(0xC0A80104, 132, 0x020000000101, 0x1070fd2fd421)
#6cec5a3dXXXX
#6c:ec:5a:3d:0d:d6/ce/c6/be