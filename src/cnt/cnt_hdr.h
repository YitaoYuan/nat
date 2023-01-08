#ifndef __LB_HDR_H__
#define __LB_HDR_H__

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
    u32 counter;
}__attribute__ ((__packed__));

struct map_entry_t{
    flow_id_t id;
    flow_val_t val;
}__attribute__ ((__packed__));

struct metadata_t{
    map_entry_t map;
    version_t   old_version;
    version_t   new_version;
    u8          type;
    switch_counter_t  main_flow_count;
    flow_num_t  index;
    checksum_t  checksum;
}__attribute__ ((__packed__));

struct hdr_t{
    ethernet_t ethernet;
    metadata_t metadata;
    ip_t ip;
    L4_header_t L4_header;
}__attribute__ ((__packed__));

#endif