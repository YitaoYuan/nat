#ifndef __NAT_HDR_H__
#define __NAT_HDR_H__

#include "../common/hdr.h"

struct flow_id_t{
    ip_addr_t   src_addr;
    ip_addr_t   dst_addr;
    port_t      src_port;
    port_t      dst_port;
    u8      protocol;
    u8      zero;
}__attribute__ ((__packed__));

struct flow_val_t{
    ip_addr_t wan_addr;
    port_t wan_port;
}__attribute__ ((__packed__));

struct map_entry_t{
    flow_id_t id;
    flow_val_t val;
}__attribute__ ((__packed__));

struct hdr_t{
    ethernet_t ethernet;
    ip_t ip;
    udp_t udp;// udp is the same port position
}__attribute__ ((__packed__));

#endif