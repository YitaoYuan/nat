/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "shared_metadata.h"

typedef bit<9>  egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ip4_addr_t;
typedef bit<16> port_t;
typedef bit<16> index_t;
typedef bit<32> time_t;

const bit<9>  NFV_PORT = 2;

const bit<8>  TCP_PROTOCOL = 0x06;
const bit<8>  UDP_PROTOCOL = 0x11;
const bit<8>  ICMP_PROTOCOL = 0x01;

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_METADATA = SHARED_TYPE_METADATA;

//you can change these by tables to support dynamic & multiple LAN address allocation
const ip4_addr_t LAN_ADDR_START = SHARED_LAN_ADDR_START;// 192.168.11.0
const ip4_addr_t LAN_ADDR_END = SHARED_LAN_ADDR_END;// not included
const ip4_addr_t NAT_ADDR = SHARED_NAT_ADDR;// 10.1.1.1

const port_t PORT_MIN = SHARED_PORT_MIN;
const bit<32> PORT_MAX = SHARED_PORT_MAX;//65536;// not included
const port_t SWITCH_PORT_NUM = SHARED_SWITCH_PORT_NUM;//50000;
const port_t NFV_PORT_NUM = (port_t)(PORT_MAX - (bit<32>)PORT_MIN) - SWITCH_PORT_NUM;

const time_t AGING_TIME_US = SHARED_AGING_TIME_US;// 1 s

const mac_addr_t SWITCH_INNER_MAC = SHARED_SWITCH_INNER_MAC;
const mac_addr_t NFV_INNER_MAC = SHARED_NFV_INNER_MAC;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ether_type;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    unused1;
    bit<16>   total_length;
    bit<32>   unused2;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   checksum;
    ip4_addr_t src_addr;
    ip4_addr_t dst_addr;
}

struct ipv4_flow_id_t { // size == 14
    ip4_addr_t   src_addr;
    ip4_addr_t   dst_addr;
    port_t      src_port;
    port_t      dst_port;
    bit<8>      protocol;
    bit<8>      zero;// zero == 0x00, for alignment in C
}

struct map_entry_t {// size == 16
    ipv4_flow_id_t  id;
    port_t          eport;
}

struct vector_entry_t {// size == 24
    map_entry_t map;
    time_t      primary_time;
    time_t      secondary_time;
}

header tcp_t{
    port_t src_port;
    port_t dst_port;
    bit<96> unused1;
    bit<16> checksum;
    bit<16> unused2;
}

header udp_t{
    port_t src_port;
    port_t dst_port;
    bit<16> unused;
    bit<16> checksum;
}

header_union L4_header_t {
    tcp_t tcp;
    udp_t udp;
}

struct metadata {
    bool parse_error;
    bool checksum_error;
    bool control_ignore;
    bool is_from_nfv;

    ipv4_flow_id_t  id;

    index_t         index;
    vector_entry_t  entry;

    time_t          time;
    bool            primary_timeout;
    bool            secondary_timeout;
    bool            match;

    bool            verify_metadata;
    bool            verify_ip;
    bool            verify_tcp;
    bool            verify_udp;

    bool            is_tcp;

    bool            update_metadata;
    bool            update_ip;
    bool            update_tcp;
    bool            update_udp;

    bit<16>         L4_length;
    bit<16>         L4_checksum_partial;
}

header nat_metadata_t {//36
    map_entry_t primary_map;//！！！！！！！！！！！！！！！！！写小程序验证一下服务器不允许在header里写struct
    map_entry_t secondary_map;

    bit         is_to_in;//最终会去往in
    bit         is_to_out;
    bit         is_update;

    bit<13>     zero;

    index_t index; // index is the hash value of flow id
    time_t sw_time;
    time_t nfv_time;// 因为一个ACK返回的时候wait_entry可能已经没了，所以时间需要记录在packet里
    bit<16> checksum;
}

struct headers {
    ethernet_t          ethernet;
    nat_metadata_t      metadata;
    ipv4_t              ipv4;
    L4_header_t         L4_header;
}



/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4: parse_ipv4;
            TYPE_METADATA: parse_metadata;
            default: myreject;
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        meta.verify_metadata = hdr.metadata.isValid();
        transition select(hdr.metadata.is_update) {
            1w0: parse_ipv4;
            1w1: myaccept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.verify_ip = hdr.ipv4.isValid();
        meta.L4_length = hdr.ipv4.total_length - (bit<16>)hdr.ipv4.ihl * 4;
        //verify(hdr.ipv4.version == 4, error.NoMatch);
        //verify(hdr.ipv4.ihl == 5, error.NoMatch);// drop all packet with ihl > 5
        bit chk = (bit)(hdr.ipv4.version == 4 && hdr.ipv4.ihl == 5);
        transition select(hdr.ipv4.protocol ++ chk) {
            TCP_PROTOCOL ++ 1w1: parse_tcp;
            UDP_PROTOCOL ++ 1w1: parse_udp;
            default: myreject;
        }
    }

    state parse_tcp {
        packet.extract(hdr.L4_header.tcp);
        meta.verify_tcp = hdr.L4_header.tcp.isValid();
        meta.is_tcp = true;
        transition myaccept;
    }

    state parse_udp {
        packet.extract(hdr.L4_header.udp);
        meta.is_tcp = false;
        meta.verify_udp = hdr.L4_header.udp.isValid() && hdr.L4_header.udp.checksum != 0;
        transition myaccept;
    }

    state myreject {
        meta.parse_error = true;
        transition accept;
    }

    state myaccept {
        meta.parse_error = false;
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control UnusedVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply{

    }
}


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        bit<16> checksum;
        meta.checksum_error = false;
        if(meta.verify_metadata) {
            hash(checksum, HashAlgorithm.csum16, 32w0,
            {hdr.metadata.primary_map.id.src_addr, 
            hdr.metadata.primary_map.id.dst_addr, 
            hdr.metadata.primary_map.id.src_port, 
            hdr.metadata.primary_map.id.dst_port, 
            hdr.metadata.primary_map.id.protocol,
            hdr.metadata.primary_map.id.zero,
            hdr.metadata.primary_map.eport,

            hdr.metadata.secondary_map.id.src_addr, 
            hdr.metadata.secondary_map.id.dst_addr, 
            hdr.metadata.secondary_map.id.src_port, 
            hdr.metadata.secondary_map.id.dst_port, 
            hdr.metadata.secondary_map.id.protocol,
            hdr.metadata.secondary_map.id.zero,
            hdr.metadata.secondary_map.eport,

            hdr.metadata.is_to_in,
            hdr.metadata.is_to_out,
            hdr.metadata.is_update,
            hdr.metadata.zero,

            hdr.metadata.index,
            
            hdr.metadata.sw_time,
            hdr.metadata.nfv_time}, 
            32w1<<16);
            if(checksum != hdr.metadata.checksum) {
                meta.checksum_error = true;
                return;
            }
        }
        
        if(meta.verify_ip) {
            hash(checksum, HashAlgorithm.csum16, 32w0,
            {hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.unused1,
            hdr.ipv4.total_length,
            hdr.ipv4.unused2,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr}, 
            32w1<<16);
            if(checksum != hdr.ipv4.checksum) {
                meta.checksum_error = true;
                return;
            }
        }
        
        if(meta.verify_tcp) {
            hash(checksum, HashAlgorithm.csum16, 32w0,
            {hdr.ipv4.src_addr, 
            hdr.ipv4.dst_addr,
            8w0,
            hdr.ipv4.protocol,
            meta.L4_length,

            hdr.L4_header.tcp.src_port,
            hdr.L4_header.tcp.dst_port,
            hdr.L4_header.tcp.unused1,
            hdr.L4_header.tcp.unused2}, 
            32w1<<16);
            meta.L4_checksum_partial = checksum;
        }
        
        if(meta.verify_udp) {
            hash(checksum, HashAlgorithm.csum16, 32w0,
            {hdr.ipv4.src_addr, 
            hdr.ipv4.dst_addr,
            8w0,
            hdr.ipv4.protocol,
            meta.L4_length,

            hdr.L4_header.udp.src_port,
            hdr.L4_header.udp.dst_port,
            hdr.L4_header.udp.unused}, 
            32w1<<16);
            meta.L4_checksum_partial = checksum;
        }
        
        /*
        verify_checksum(meta.verify_metadata, 
            {hdr.metadata.primary_map.id.src_addr, 
            hdr.metadata.primary_map.id.dst_addr, 
            hdr.metadata.primary_map.id.src_port, 
            hdr.metadata.primary_map.id.dst_port, 
            hdr.metadata.primary_map.id.protocol,
            hdr.metadata.primary_map.id.zero,
            hdr.metadata.primary_map.eport,

            hdr.metadata.secondary_map.id.src_addr, 
            hdr.metadata.secondary_map.id.dst_addr, 
            hdr.metadata.secondary_map.id.src_port, 
            hdr.metadata.secondary_map.id.dst_port, 
            hdr.metadata.secondary_map.id.protocol,
            hdr.metadata.secondary_map.id.zero,
            hdr.metadata.secondary_map.eport,

            hdr.metadata.is_to_in,
            hdr.metadata.is_to_out,
            hdr.metadata.is_update,
            hdr.metadata.zero,

            hdr.metadata.index,
            
            hdr.metadata.sw_time,
            hdr.metadata.nfv_time
            },
            hdr.metadata.checksum, HashAlgorithm.csum16);

        verify_checksum(meta.verify_ip, 
            {hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.unused1,
            hdr.ipv4.total_length,
            hdr.ipv4.unused2,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr},
            hdr.ipv4.checksum, HashAlgorithm.csum16);
        
        verify_checksum_with_payload(meta.verify_tcp, 
            {hdr.ipv4.src_addr, 
            hdr.ipv4.dst_addr,
            8w0,
            hdr.ipv4.protocol,
            meta.L4_length,

            hdr.L4_header.tcp.src_port,
            hdr.L4_header.tcp.dst_port,
            hdr.L4_header.tcp.unused1,
            hdr.L4_header.tcp.unused2}, 
            hdr.L4_header.tcp.checksum, HashAlgorithm.csum16);

        verify_checksum_with_payload(meta.verify_udp, 
            {hdr.ipv4.src_addr, 
            hdr.ipv4.dst_addr,
            8w0,
            hdr.ipv4.protocol,
            meta.L4_length,

            hdr.L4_header.udp.src_port,
            hdr.L4_header.udp.dst_port,
            hdr.L4_header.udp.unused}, 
            hdr.L4_header.udp.checksum, HashAlgorithm.csum16);
        */
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(bit<9> port, mac_addr_t dmac) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ip2port_dmac{
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 16;
        default_action = drop();
    }

    // type只能是bit<n>，并且据说宽度>64不行，p4和simple_switch支持，但thrift不支持。
    register<bit<32> >((bit<32>)SWITCH_PORT_NUM) map5; // id -> index -> eport
    register<bit<32> >((bit<32>)SWITCH_PORT_NUM) map4;
    register<bit<32> >((bit<32>)SWITCH_PORT_NUM) map3;
    register<bit<32> >((bit<32>)SWITCH_PORT_NUM) map2;
    register<bit<32> >((bit<32>)SWITCH_PORT_NUM) map1;
    register<bit<32> >((bit<32>)SWITCH_PORT_NUM) map0;
    //拆成6个，是因为simple_switch_CLI只支持显示到2^63-1

    register<bit<16> >(PORT_MAX - (bit<32>)PORT_MIN) reverse_map; // eport -> index

    action map_read(out vector_entry_t entry, in index_t index) {
        bit<32> tmp5 = 0;
        bit<32> tmp4 = 0;
        bit<32> tmp3 = 0;
        bit<32> tmp2 = 0;
        bit<32> tmp1 = 0;
        bit<32> tmp0 = 0;
        map5.read(tmp5, (bit<32>)index);
        map4.read(tmp4, (bit<32>)index);
        map3.read(tmp3, (bit<32>)index);
        map2.read(tmp2, (bit<32>)index);
        map1.read(tmp1, (bit<32>)index);
        map0.read(tmp0, (bit<32>)index);
        entry = {{{tmp5[31:0], tmp4[31:0], tmp3[31:16], tmp3[15:0], tmp2[31:24], tmp2[23:16]}, tmp2[15:0]}, tmp1[31:0], tmp0[31:0]};
    }

    action map_write(in index_t index, in vector_entry_t entry) {
        map_entry_t map_entry = entry.map;
        ipv4_flow_id_t id = map_entry.id;
        bit<32> tmp5 = id.src_addr;
        bit<32> tmp4 = id.dst_addr; 
        bit<32> tmp3 = id.src_port ++ id.dst_port;
        bit<32> tmp2 = id.protocol ++ id.zero ++ map_entry.eport;
        bit<32> tmp1 = entry.primary_time;
        bit<32> tmp0 = entry.secondary_time;
        map5.write((bit<32>)index, tmp5);
        map4.write((bit<32>)index, tmp4);
        map3.write((bit<32>)index, tmp3);
        map2.write((bit<32>)index, tmp2);
        map1.write((bit<32>)index, tmp1);
        map0.write((bit<32>)index, tmp0);
    }

    action get_transition_type() {

        meta.control_ignore = false;

        if(standard_metadata.ingress_port == NFV_PORT) {

            meta.is_from_nfv = true;

            if(hdr.ethernet.src_addr != NFV_INNER_MAC || 
                hdr.ethernet.dst_addr != SWITCH_INNER_MAC ||
                hdr.ethernet.ether_type != TYPE_METADATA) {// parser didn't check this
                meta.control_ignore = true;
                return;
            }
            if(hdr.metadata.zero != 0) {
                meta.control_ignore = true;
                return;
            }
            if( (bit<2>)hdr.metadata.is_to_in +
                (bit<2>)hdr.metadata.is_to_out +
                (bit<2>)hdr.metadata.is_update != 1) {
                meta.control_ignore = true;
                return;
            } 
        }
        else {
            meta.is_from_nfv = false;

            if(LAN_ADDR_START <= hdr.ipv4.src_addr && hdr.ipv4.src_addr < LAN_ADDR_END
                && !(LAN_ADDR_START <= hdr.ipv4.dst_addr && hdr.ipv4.dst_addr < LAN_ADDR_END)) {
                hdr.metadata.is_to_in = 0;
                hdr.metadata.is_to_out = 1;
            }
            else if(!(LAN_ADDR_START <= hdr.ipv4.src_addr && hdr.ipv4.src_addr < LAN_ADDR_END) 
                && hdr.ipv4.dst_addr == NAT_ADDR) {
                hdr.metadata.is_to_in = 1;
                hdr.metadata.is_to_out = 0;
            }
            else {
                meta.control_ignore = true;
                return;
            }
        }
    }

    action get_id() {
        if(meta.is_tcp) {
            meta.id.src_port = hdr.L4_header.tcp.src_port;
            meta.id.dst_port = hdr.L4_header.tcp.dst_port;
        }
        else {
            meta.id.src_port = hdr.L4_header.udp.src_port;
            meta.id.dst_port = hdr.L4_header.udp.dst_port;
        }
        meta.id.src_addr = hdr.ipv4.src_addr;
        meta.id.dst_addr = hdr.ipv4.dst_addr;
        meta.id.protocol = hdr.ipv4.protocol;
        meta.id.zero = 0;
    }

    action get_index() {
        ipv4_flow_id_t id = meta.id;
        hash(meta.index, HashAlgorithm.crc16, (index_t)1, 
        {id.src_addr, id.dst_addr, id.src_port, id.dst_port, id.protocol, id.zero}, 
        (index_t)SWITCH_PORT_NUM-1);
        // port PORT_MIN and index 0 is reserved
    }

    action get_time() {
        meta.time = (bit<32>)standard_metadata.ingress_global_timestamp;//truncate 48->32
    }    

    action read_entry() {
        map_read(meta.entry, meta.index);

        meta.primary_timeout = meta.time - meta.entry.primary_time > AGING_TIME_US;
        meta.secondary_timeout = meta.time - meta.entry.secondary_time > AGING_TIME_US;
        meta.match = meta.entry.map.id == meta.id;
    }

    action translate() {
        hdr.ipv4.src_addr = NAT_ADDR;
        if(meta.is_tcp) 
            hdr.L4_header.tcp.src_port = meta.entry.map.eport;
        else
            hdr.L4_header.udp.src_port = meta.entry.map.eport;
    }
    
    action reverse_translate() {
        hdr.ipv4.dst_addr = meta.entry.map.id.src_addr;
        if(meta.is_tcp)
            hdr.L4_header.tcp.dst_port = meta.entry.map.id.src_port;
        else
            hdr.L4_header.udp.dst_port = meta.entry.map.id.src_port;
    }

    action set_metadata(bool send_update) {
        hdr.ethernet.ether_type = TYPE_METADATA;
        hdr.metadata.primary_map = meta.entry.map;
        hdr.metadata.secondary_map = {meta.id, 0};
        //hdr.metadata.is_to_in
        //hdr.metadata.is_to_out
        hdr.metadata.is_update = send_update ? (bit)meta.primary_timeout : 1w0;
        hdr.metadata.zero = 0;
        hdr.metadata.index = meta.index;
        hdr.metadata.sw_time = meta.time;
        hdr.metadata.nfv_time = 0;
        hdr.metadata.checksum = 0;
    }

    action send_to_NFV() {
        standard_metadata.egress_spec = 2;
        hdr.ethernet.src_addr = 48w1;
        hdr.ethernet.dst_addr = 48w2;
    }

    apply {
        MyVerifyChecksum.apply(hdr, meta);

        if(meta.parse_error || meta.checksum_error || standard_metadata.checksum_error != 0) {
            drop();
            return;
        }
        //if(hdr.ethernet.ether_type != TYPE_IPV4) {drop(); return;}
        // TODO******************************************************************
        // 还需要判断下DSTMAC是不是本地端口的MAC
        if(!hdr.metadata.isValid()) hdr.metadata.setValid();

        get_time();
        get_transition_type();

        if(meta.control_ignore) {
            drop();
            return;
        }
        
        if(!meta.is_from_nfv && hdr.metadata.is_to_in == 1) {
            port_t eport = meta.is_tcp? hdr.L4_header.tcp.dst_port : hdr.L4_header.udp.dst_port;
            port_t src_port = meta.is_tcp? hdr.L4_header.tcp.src_port : hdr.L4_header.udp.src_port;
            ip4_addr_t src_addr = hdr.ipv4.src_addr;
            bit<8> protocol = hdr.ipv4.protocol;

            
            if(eport <= PORT_MIN || (bit<32>)eport >= PORT_MAX) {
                drop();
                return;
            }

            reverse_map.read(meta.index, (bit<32>)(eport - PORT_MIN));

            if(meta.index == 0) { // not in switch
                set_metadata(false);
                send_to_NFV();
                return;
            }

            //assert(meta.index < SWITCH_PORT_NUM); //

            map_read(meta.entry, meta.index);

            if(meta.entry.map.eport != eport) {//这个if是冗余的,因为不用的reverse_map会置零
                set_metadata(false);
                send_to_NFV();
                return;
            }

            ipv4_flow_id_t map_id = meta.entry.map.id;

            if({map_id.dst_addr, map_id.dst_port, map_id.protocol} != {src_addr, src_port, protocol}
                || meta.time - meta.entry.primary_time > AGING_TIME_US) {// mismatch or aging
                drop();
                return;
            }
            meta.entry.primary_time = meta.time;
            map_write(meta.index, meta.entry);

            reverse_translate();
            ip2port_dmac.apply();
        }
        else if(!meta.is_from_nfv && hdr.metadata.is_to_out == 1) {
            get_id();
            get_index();

            read_entry();
            
            if(meta.entry.map.eport == 0 || (meta.primary_timeout && meta.secondary_timeout)) {
                meta.entry.map.id = meta.id;
                meta.entry.primary_time = meta.time;

                if(meta.entry.map.eport == 0) { // initialize
                    meta.entry.map.eport = meta.index + PORT_MIN;
                    reverse_map.write((bit<32>)(meta.entry.map.eport - PORT_MIN), meta.index);
                }
                map_write(meta.index, meta.entry);// need to be atomic from read to write !!!
                translate();
                ip2port_dmac.apply();
            }
            else if(!meta.primary_timeout && meta.match) {
                meta.entry.primary_time = meta.time;

                map_write(meta.index, meta.entry);
                translate();
                ip2port_dmac.apply();
            }
            else {
                meta.entry.secondary_time = meta.time;

                map_write(meta.index, meta.entry);

                set_metadata(true);
                send_to_NFV();
            } 
        }
        else if(meta.is_from_nfv && hdr.metadata.is_to_in == 1) {
            ip2port_dmac.apply();
        }
        else if(meta.is_from_nfv && hdr.metadata.is_to_out == 1) {
            ip2port_dmac.apply();
        }
        else if(meta.is_from_nfv && hdr.metadata.is_update == 1) {
            meta.index = hdr.metadata.index;

            if( meta.time - hdr.metadata.sw_time > AGING_TIME_US / 2 || 
                meta.index >= SWITCH_PORT_NUM) {
                drop();
                return;
            }

            map_read(meta.entry, meta.index);

            if(meta.entry.map != hdr.metadata.primary_map && 
                meta.entry.map != hdr.metadata.secondary_map) {
                drop();
                return;
            }
                
            
            if(meta.entry.map == hdr.metadata.primary_map) {
                meta.entry.map = hdr.metadata.secondary_map;
                meta.entry.primary_time = meta.time;

                reverse_map.write((bit<32>)(hdr.metadata.primary_map.eport - PORT_MIN), (index_t)0);
                reverse_map.write((bit<32>)(hdr.metadata.secondary_map.eport - PORT_MIN), meta.index);

                map_write(meta.index, meta.entry);
            }
            //if meta.entry.map == hdr.metadata.secondary_map return a redundent ACK

            send_to_NFV();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {

        if(meta.update_metadata) {
            hash(hdr.metadata.checksum, HashAlgorithm.csum16, 32w0,
            {hdr.metadata.primary_map.id.src_addr, 
            hdr.metadata.primary_map.id.dst_addr, 
            hdr.metadata.primary_map.id.src_port, 
            hdr.metadata.primary_map.id.dst_port, 
            hdr.metadata.primary_map.id.protocol,
            hdr.metadata.primary_map.id.zero,
            hdr.metadata.primary_map.eport,

            hdr.metadata.secondary_map.id.src_addr, 
            hdr.metadata.secondary_map.id.dst_addr, 
            hdr.metadata.secondary_map.id.src_port, 
            hdr.metadata.secondary_map.id.dst_port, 
            hdr.metadata.secondary_map.id.protocol,
            hdr.metadata.secondary_map.id.zero,
            hdr.metadata.secondary_map.eport,

            hdr.metadata.is_to_in,
            hdr.metadata.is_to_out,
            hdr.metadata.is_update,
            hdr.metadata.zero,

            hdr.metadata.index,
            
            hdr.metadata.sw_time,
            hdr.metadata.nfv_time}, 
            32w1<<16);
        }
        
        if(meta.update_ip) {
            hash(hdr.ipv4.checksum, HashAlgorithm.csum16, 32w0,
            {hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.unused1,
            hdr.ipv4.total_length,
            hdr.ipv4.unused2,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr}, 
            32w1<<16);
        }
        bit<32> checksum;
        
        if(meta.update_tcp) {
            hash(checksum, HashAlgorithm.csum16, 32w0,
            {hdr.ipv4.src_addr, 
            hdr.ipv4.dst_addr,
            8w0,
            hdr.ipv4.protocol,
            meta.L4_length,

            hdr.L4_header.tcp.src_port,
            hdr.L4_header.tcp.dst_port,
            hdr.L4_header.tcp.unused1,
            hdr.L4_header.tcp.unused2}, 
            32w1<<16);
            checksum = (bit<32>)hdr.L4_header.tcp.checksum + (checksum + (bit<32>)(0xffff^meta.L4_checksum_partial));
            checksum = (checksum & 0xffff) + (checksum >> 16);
            checksum = (checksum & 0xffff) + (checksum >> 16);
            if(checksum == 0) checksum = 0xffff;
            hdr.L4_header.tcp.checksum = (bit<16>)checksum;
        }
        
        if(meta.update_udp) {
            hash(checksum, HashAlgorithm.csum16, 32w0,
            {hdr.ipv4.src_addr, 
            hdr.ipv4.dst_addr,
            8w0,
            hdr.ipv4.protocol,
            meta.L4_length,

            hdr.L4_header.udp.src_port,
            hdr.L4_header.udp.dst_port,
            hdr.L4_header.udp.unused}, 
            32w1<<16);
            checksum = (bit<32>)hdr.L4_header.udp.checksum + (checksum + (bit<32>)(0xffff^meta.L4_checksum_partial));
            checksum = (checksum & 0xffff) + (checksum >> 16);
            checksum = (checksum & 0xffff) + (checksum >> 16);
            if(checksum == 0) checksum = 0xffff;
            hdr.L4_header.udp.checksum = (bit<16>)checksum;
        }
        /*
        update_checksum(meta.update_metadata, 
            {hdr.metadata.primary_map.id.src_addr, 
            hdr.metadata.primary_map.id.dst_addr, 
            hdr.metadata.primary_map.id.src_port, 
            hdr.metadata.primary_map.id.dst_port, 
            hdr.metadata.primary_map.id.protocol,
            hdr.metadata.primary_map.id.zero,
            hdr.metadata.primary_map.eport,

            hdr.metadata.secondary_map.id.src_addr, 
            hdr.metadata.secondary_map.id.dst_addr, 
            hdr.metadata.secondary_map.id.src_port, 
            hdr.metadata.secondary_map.id.dst_port, 
            hdr.metadata.secondary_map.id.protocol,
            hdr.metadata.secondary_map.id.zero,
            hdr.metadata.secondary_map.eport,

            hdr.metadata.is_to_in,
            hdr.metadata.is_to_out,
            hdr.metadata.is_update,
            hdr.metadata.zero,

            hdr.metadata.index,

            hdr.metadata.sw_time,
            hdr.metadata.nfv_time
            },
            hdr.metadata.checksum, HashAlgorithm.csum16);

        update_checksum(meta.update_ip, 
            {hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.unused1,
            hdr.ipv4.total_length,
            hdr.ipv4.unused2,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr},
            hdr.ipv4.checksum, HashAlgorithm.csum16);
        
        update_checksum_with_payload(meta.update_tcp, 
            {hdr.ipv4.src_addr, 
            hdr.ipv4.dst_addr,
            8w0,
            hdr.ipv4.protocol,
            meta.L4_length,

            hdr.L4_header.tcp.src_port,
            hdr.L4_header.tcp.dst_port,
            hdr.L4_header.tcp.unused1,
            hdr.L4_header.tcp.unused2}, 
            hdr.L4_header.tcp.checksum, HashAlgorithm.csum16);

        update_checksum_with_payload(meta.update_udp, 
            {hdr.ipv4.src_addr, 
            hdr.ipv4.dst_addr,
            8w0,
            hdr.ipv4.protocol,
            meta.L4_length,

            hdr.L4_header.udp.src_port,
            hdr.L4_header.udp.dst_port,
            hdr.L4_header.udp.unused}, 
            hdr.L4_header.udp.checksum, HashAlgorithm.csum16);    
        */
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action get_smac(mac_addr_t smac) {
        hdr.ethernet.src_addr = smac;
    }

    table port2smac{
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            get_smac;
        }
        size = 16;
    }

    apply{
        meta.update_metadata = hdr.metadata.isValid();
        meta.update_ip = hdr.ipv4.isValid();
        meta.update_tcp = hdr.L4_header.tcp.isValid();
        meta.update_udp = hdr.L4_header.udp.isValid() && (hdr.L4_header.udp.checksum != 0);
        if(standard_metadata.egress_port != NFV_PORT) {
            hdr.metadata.setInvalid();
            hdr.ethernet.ether_type = TYPE_IPV4;
            port2smac.apply();
        }
        MyComputeChecksum.apply(hdr, meta);
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control UnusedComputeChecksum(inout headers hdr, inout metadata meta) {
    apply{

    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.metadata);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.L4_header);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
UnusedVerifyChecksum(),
MyIngress(),
MyEgress(),
UnusedComputeChecksum(),
MyDeparser()
) main;
