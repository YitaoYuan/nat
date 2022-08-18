/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

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
const bit<16> TYPE_METADATA = 0x1234;

//you can change these by tables to support dynamic & multiple LAN address allocation
const ip4_addr_t LAN_ADDR_START = 0xa0010100;// 192.168.11.0
const ip4_addr_t LAN_ADDR_END = 0xa0010200;// not included
const ip4_addr_t NAT_ADDR = 0xb0010101;// 10.1.1.1


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
    tcp_t               tcp;
    udp_t               udp;
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
        }
    }

    state parse_metadata {
        packet.extract(hdr.metadata);
        transition select(hdr.metadata.is_update) {
            1w0: parse_ipv4;
            1w1: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL: parse_tcp;
            UDP_PROTOCOL: parse_udp;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
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
    
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply{
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {

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
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
