#include <cstdio>
#include <cstring>
#include <pcap/pcap.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <unordered_map>
#include <queue>
#include "shared_metadata.h"

using std::unordered_map;
using std::queue;
using std::make_pair;

typedef unsigned short port_t;
typedef unsigned int ip_addr_t;
typedef unsigned long long mytime_t;
typedef unsigned short len_t;
typedef unsigned short checksum_t;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

/*
 * Without additional specification, all value in these structs are in network byte order
 */
struct ethernet_t{
    u8 dst_addr[6];
    u8 src_addr[6];
    u16 ether_type;
}__attribute__ ((__packed__));

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

struct map_entry_t{
    flow_id_t id;
    port_t eport;
}__attribute__ ((__packed__));

enum message_t: u16{
    null = 0x0000,
    timeout = 0x0100,
    require_update = 0x0200,
    accept_update = 0x0300,
    reject_update = 0x0400
};

struct update_t{
    map_entry_t primary_map; 
    map_entry_t secondary_map;
    message_t type;
    checksum_t checksum;
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
}__attribute__ ((__packed__));

struct udp_t{
    port_t src_port;
    port_t dst_port;
    u8 unused[2];
    checksum_t checksum;
}__attribute__ ((__packed__));

union L4_header_t{
    tcp_t tcp;
    udp_t udp;
};

struct forward_hdr_t{
    ethernet_t ethernet;
    update_t update;
    ip_t ip;
    L4_header_t L4_header;
};

struct backward_hdr_t{
    ethernet_t ethernet;
    ip_t ip;
    L4_header_t L4_header;
};

struct map_val_t{
    port_t eport_host;
    mytime_t timestamp_host;// host order
};

struct Hash{
    size_t operator ()(const flow_id_t &id) const{
        return (u64)id.src_addr ^ (u64)id.dst_addr << 32 ^ 
            (u64)id.src_port ^ (u64)id.dst_port << 16 ^ (u64)id.protocol << 32;
    }
};

/*
 * All these consts are in host's byte order
 */

const ip_addr_t LAN_ADDR_START = SHARED_LAN_ADDR_START;
const ip_addr_t LAN_ADDR_END = SHARED_LAN_ADDR_END;// not included
const ip_addr_t NAT_ADDR = SHARED_NAT_ADDR;

const port_t PORT_MIN = SHARED_PORT_MIN;
const u32 PORT_MAX = SHARED_PORT_MAX;// not included
const port_t SWITCH_PORT_NUM = SHARED_SWITCH_PORT_NUM;
const port_t NFV_PORT_NUM = PORT_MAX - PORT_MIN - SWITCH_PORT_NUM;

const u32 AGING_TIME_US = SHARED_AGING_TIME_US;

const u16 TYPE_IPV4 = 0x800;
const u16 TYPE_UPDATE = 0x88B5;

const u8 TCP_PROTOCOL = 0x06;
const u8 UDP_PROTOCOL = 0x11;

const u32 max_frame_size = 1514;

pcap_t *device;

u8 buf[max_frame_size] __attribute__ ((aligned (64)));

unordered_map<flow_id_t, map_val_t, Hash>map;
flow_id_t reverse_map[PORT_MAX - PORT_MIN];
queue<port_t>free_port;


void stop(int signo)
{
    _exit(0);
}

void nfv_init()
{
    for(port_t p = PORT_MIN + SWITCH_PORT_NUM; p < PORT_MAX; p++)
        free_port.push(p);
}

checksum_t verify_checksum(forward_hdr_t * const hdr) {
    /*
    It is acceptable to only verify checksum of header "update"
    because we have aging mechanism.
    Wrong flow state will be removed by that.
    */
    checksum_t *l = (checksum_t *)&hdr->update;
    checksum_t *r = (checksum_t *)((u8*)&hdr->update + sizeof(hdr->update));
    u32 res = 0;
    for(checksum_t *i = l; i < r; i++) res += ntohs(*i);
    res = (res & 0xffff) + (res >> 16);
    res = (res & 0xffff) + (res >> 16);
    return ~(checksum_t)res;
}

inline checksum_t negative(checksum_t x) {
    //将x的补码表示看成二进制串
    //将二进制串看成反码表示
    //对反码表示求负
    return ~x;    
}

inline checksum_t add(checksum_t x, checksum_t y) {
    //将二进制串看成反码表示
    //对反码表示求和
    u32 res = (u32)x + (u32)y;
    return (checksum_t)((res & 0xffff) + (res >> 16));
}

inline checksum_t sub(checksum_t x, checksum_t y) {
    return add(x, negative(y));
}

inline checksum_t make_zero_negative(checksum_t x) {
    //将反码+0变为-0
    return x == 0 ? ~x : x;
}

void forward_process(mytime_t timestamp, len_t packet_len, forward_hdr_t * const hdr)
{
// verify
    if(packet_len < sizeof(ethernet_t) + sizeof(update_t) + sizeof(ip_t)) return;
    if(hdr->ip.src_addr != hdr->update.secondary_map.id.src_addr 
        || hdr->ip.dst_addr != hdr->update.secondary_map.id.dst_addr 
        || hdr->ip.protocol != hdr->update.secondary_map.id.protocol)
        return;
    bool is_tcp;
    if(hdr->ip.protocol == TCP_PROTOCOL) {// 8 bit, OK
        if(packet_len < sizeof(ethernet_t) + sizeof(update_t) + sizeof(ip_t) + sizeof(tcp_t))
            return;
        if(hdr->L4_header.tcp.src_port != hdr->update.secondary_map.id.src_port
            || hdr->L4_header.tcp.dst_port != hdr->update.secondary_map.id.dst_port)
            return;
        is_tcp = 1;
    }
    else if(hdr->ip.protocol == UDP_PROTOCOL) {
        if(packet_len < sizeof(ethernet_t) + sizeof(update_t) + sizeof(ip_t) + sizeof(udp_t))
            return;
        if(hdr->L4_header.udp.src_port != hdr->update.secondary_map.id.src_port
            || hdr->L4_header.udp.dst_port != hdr->update.secondary_map.id.dst_port)
            return;
        is_tcp = 0;
    }
    else return;

    if(verify_checksum(hdr) != 0) return;

// allocate flow state for new flow
    update_t &update = hdr->update;
    // things in map are in network byte order
    auto it = map.find(update.secondary_map.id);
    if(it == map.end()) {// a new flow
        if(free_port.empty()) return;// no port available, drop
        port_t eport_host = free_port.front();// host
        free_port.pop();

        it = map.insert(make_pair(update.secondary_map.id,
                (map_val_t){eport_host/*h*/, timestamp/*h*/})).first;

        reverse_map[eport_host - PORT_MIN] = update.secondary_map.id;
    }

// refresh flow's timestamp
    it->second.timestamp_host = timestamp;// host

// translate
    checksum_t delta = 0;// host
    delta = add(delta, sub(NAT_ADDR >> 16, ntohs(hdr->ip.src_addr & 0xffff)));
    delta = add(delta, sub(NAT_ADDR & 0xffff, ntohs(hdr->ip.src_addr >> 16)));
    hdr->ip.src_addr = htonl(NAT_ADDR);
    // If the original checksum is wrong, the new one will also be wrong, 
    // and the packet will be droped by switch later.
    hdr->ip.checksum = htons(make_zero_negative(sub(ntohs(hdr->ip.checksum), delta)));
    if(is_tcp) {
        delta = add(delta, sub(it->second.eport_host, ntohs(hdr->L4_header.tcp.src_port)));
        hdr->L4_header.tcp.src_port = htons(it->second.eport_host);// h2n
        hdr->L4_header.tcp.checksum = htons(make_zero_negative(sub(ntohs(hdr->L4_header.tcp.checksum), delta)));
    }
    else {
        delta = add(delta, sub(it->second.eport_host, ntohs(hdr->L4_header.udp.src_port)));
        hdr->L4_header.udp.src_port = htons(it->second.eport_host);
        if(hdr->L4_header.udp.checksum != 0)// 0 is same for n & h
            hdr->L4_header.udp.checksum = htons(make_zero_negative(sub(ntohs(hdr->L4_header.udp.checksum), delta)));
    }

// TODO*************************************
// choose whether to require a switch update (set hdr->update.type)

// send back
    pcap_sendpacket(device, (u_char *)hdr, packet_len);
}

void backward_process(mytime_t timestamp, len_t packet_len, backward_hdr_t * const hdr)
{
// verify
    if(packet_len < sizeof(ethernet_t) + sizeof(ip_t)) return;

    bool is_tcp;
    ip_addr_t src_addr = hdr->ip.src_addr;
    port_t eport, src_port;
    if(hdr->ip.protocol == TCP_PROTOCOL) {// 8 bit, OK
        if(packet_len < sizeof(ethernet_t) + sizeof(ip_t) + sizeof(tcp_t))
            return;
        is_tcp = 1;
        eport = hdr->L4_header.tcp.dst_port;
        src_port = hdr->L4_header.tcp.src_port;
    }
    else if(hdr->ip.protocol == UDP_PROTOCOL) {
        if(packet_len < sizeof(ethernet_t) + sizeof(ip_t) + sizeof(udp_t))
            return;
        is_tcp = 0;
        eport = hdr->L4_header.udp.dst_port;
        src_port = hdr->L4_header.udp.src_port;
    }
    else return;

    if(ntohs(eport) <= PORT_MIN || ntohs(eport) >= PORT_MAX) return;

// match
    flow_id_t &flow_id = reverse_map[ntohs(eport) - PORT_MIN];// index is in h form
    if(flow_id.dst_addr != src_addr || flow_id.dst_port != src_port 
        || flow_id.protocol != hdr->ip.protocol)
        return; // drop on mismatch
    auto it = map.find(flow_id);
    if(it == map.end() || htons(it->second.eport_host) != eport || timestamp - it->second.timestamp_host > AGING_TIME_US)
        return; // drop on mismatch or aging

// refresh flow's timestamp
    it->second.timestamp_host = timestamp;

// tranlate
    checksum_t delta = 0;// host
    delta = add(delta, sub(ntohs(flow_id.src_addr & 0xffff), ntohs(hdr->ip.dst_addr & 0xffff)));
    delta = add(delta, sub(ntohs(flow_id.src_addr >> 16), ntohs(hdr->ip.dst_addr >> 16)));
    hdr->ip.dst_addr = flow_id.src_addr;
    hdr->ip.checksum = htons(make_zero_negative(sub(ntohs(hdr->ip.checksum), delta)));
    if(is_tcp) {
        delta = add(delta, sub(ntohs(flow_id.src_port), ntohs(hdr->L4_header.tcp.dst_port)));
        hdr->L4_header.tcp.dst_port = flow_id.src_port;
        hdr->L4_header.tcp.checksum = htons(make_zero_negative(sub(ntohs(hdr->L4_header.tcp.checksum), delta)));
    }
    else {
        delta = add(delta, sub(ntohs(flow_id.src_port), ntohs(hdr->L4_header.udp.dst_port)));
        hdr->L4_header.udp.dst_port = flow_id.src_port;
        if(hdr->L4_header.udp.checksum != 0)
            hdr->L4_header.udp.checksum = htons(make_zero_negative(sub(ntohs(hdr->L4_header.udp.checksum), delta)));
    }

// send back
    pcap_sendpacket(device, (u_char *)hdr, packet_len);
}

void ack_process(mytime_t timestamp, len_t packet_len, forward_hdr_t * hdr)
{

}

void nat_process(mytime_t timestamp, len_t packet_len, forward_hdr_t * hdr)
{
    if(hdr->ethernet.ether_type == htons(TYPE_UPDATE)) {
        if(packet_len < sizeof(ethernet_t) + sizeof(update_t)) return;

        if(hdr->update.type == message_t::accept_update || hdr->update.type == message_t::reject_update)
            ack_process(timestamp, packet_len, hdr);
        else if(hdr->update.type == message_t::null || hdr->update.type == message_t::timeout) 
            forward_process(timestamp, packet_len, hdr);
    }
    else if(hdr->ethernet.ether_type == htons(TYPE_IPV4)) 
        backward_process(timestamp, packet_len, (backward_hdr_t *) hdr);
}

void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    fprintf(stderr, "a packet\n");
    //h->ts.tv_sec/tv_usec
    //h->caplen
    //h->len
    if(h->caplen != h->len) return;
    if(h->len < sizeof(ethernet_t)) return;
    memcpy(buf, bytes, h->len);
    nat_process(h->ts.tv_sec * 1000000ull + h->ts.tv_usec, h->len, (forward_hdr_t*)buf);
}

int main(int argc, char **argv)
{
    assert((long long)buf % 64 == 0);
    if(argc != 2) {
        printf("Usage: nfv ifname\n");
        return 0;
    }
    char *dev_name = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    device = pcap_open_live(dev_name, max_frame_size, 1, 1, errbuf);
    
    if(device == NULL) {
        printf("cannot open device\n");
        puts(errbuf);
        return 0;
    }

    signal(SIGINT, stop);

    nfv_init();

    pcap_loop(device, -1, pcap_handle, NULL);
    return 0;
}
