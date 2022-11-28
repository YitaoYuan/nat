#ifndef __HDR_H__
#define __HDR_H__

#include "type.h"

/*
 * Without additional specification, all value in these structs are in network byte order
 */
struct ethernet_t{
    u8 dst_addr[6];
    u8 src_addr[6];
    u16 ether_type;
}__attribute__ ((__packed__));

struct ip_t{
    u8 unused[9];
    u8 protocol;
    checksum_t checksum;
    ip_addr_t src_addr;
    ip_addr_t dst_addr;
}__attribute__ ((__packed__));

struct tcp_t{
    port_t src_port;
    port_t dst_port;
    u8 unused1[12];
    checksum_t checksum;
    u8 unused2[2];
    char payload[];
}__attribute__ ((__packed__));

struct udp_t{
    port_t src_port;
    port_t dst_port;
    u8 unused[2];
    checksum_t checksum;
    char payload[];
}__attribute__ ((__packed__));

union L4_header_t{
    tcp_t tcp;
    udp_t udp;
};

#endif