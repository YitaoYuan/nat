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

struct metadata_t{
    map_entry_t map;
    version_t   old_version;
    version_t   new_version;
    u8          update : 4;
    u8          type   : 4;
    u8          zero2;
    flow_num_t  index;
    switch_time_t    switch_time;
    checksum_t  checksum;
}__attribute__ ((__packed__));

struct hdr_t{
    ethernet_t ethernet;
    metadata_t metadata;
    ip_t ip;
    L4_header_t L4_header;
};

#endif