#ifndef __HDR_H__
#define __HDR_H__

#include "type.h"

/*
 * Without additional specification, all value in these structs are in network byte order
 */

struct flow_id_t{
    ip_addr_t   src_addr;
    ip_addr_t   dst_addr;
    port_t      src_port;
    port_t      dst_port;
    u8      protocol;
    u8      zero;
    bool operator == (const flow_id_t &y) const{ 
        return memcmp(this, &y, sizeof(y)) == 0;
    }
}__attribute__ ((__packed__));

struct flow_val_t{
    ip_addr_t wan_addr;
    port_t wan_port;
}__attribute__ ((__packed__));

struct map_entry_t{
    flow_id_t id;
    flow_val_t val;
}__attribute__ ((__packed__));


struct ethernet_t{
    u8 dst_addr[6];
    u8 src_addr[6];
    u16 ether_type;
}__attribute__ ((__packed__));

struct nat_metadata_t{
    map_entry_t map;
    version_t   version;
    u8          update : 4;
    u8          type   : 4;
    switch_time_t    switch_time;
    flow_num_t  index;
    checksum_t  checksum;
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

struct hdr_t{
    ethernet_t ethernet;
    nat_metadata_t metadata;
    ip_t ip;
    L4_header_t L4_header;
};

#endif