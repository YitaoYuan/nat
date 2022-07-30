#include <cstdio>
#include <cstring>
#include <pcap/pcap.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <unordered_map>
#include <queue>
using std::queue;
using std::unordered_map;
using namespace std;
#include "shared_metadata.h"

typedef unsigned short port_t;
typedef unsigned int ip_addr_t;
typedef unsigned long long mytime_t;
typedef unsigned short len_t;
typedef unsigned short checksum_t;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

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
    bool operator == (){
        //todo
    }
}__attribute__ ((__packed__));

struct map_entry_t{
    flow_id_t id;
    port_t eport;
}__attribute__ ((__packed__));

enum message_t: u16{
    null = 0,
    timeout = 1,
    require_update = 2,
    accept_update = 3,
    reject_update = 4
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
    port_t eport;
    mytime_t timestamp;
}

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

unordered_map<flow_id_t, map_val_t>map;
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

checksum_t verify_checksum() {
    /*
    It is acceptable to only verify checksum of header "update"
    because we have aging mechanism.
    Wrong flow state will be removed by that.
    */
    checksum_t *l = (checksum_t *)&hdr.update;
    checksum_t *r = (checksum_t *)((u8*)&hdr.update + sizeof(hdr.update));
    u32 res = 0;
    for(checksum_t *i = l; i < r; i++) res += *i;
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

void forward_process(mytime_t ts, len_t packet_len, forward_hdr_t * const hdr)
{
// verify
    if(packet_len < sizeof(ethernet_t) + sizeof(update_t) + sizeof(ip_t)) return;
    if(hdr.ip.src_addr != hdr.update.secondary_map.id.src_addr 
        || hdr.ip.dst_addr != hdr.update.secondary_map.id.dst_addr 
        || hdr.ip.protocol != hdr.update.secondary_map.id.protocol)
        return;
    bool is_tcp;
    if(hdr.ip.protocol == TCP_PROTOCOL) {
        if(packet_len < sizeof(ethernet_t) + sizeof(update_t) + sizeof(ip_t) + sizeof(tcp_t))
            return;
        if(hdr.tcp.src_port != hdr.update.secondary_map.id.src_port
            || hdr.tcp.dst_port != hdr.update.secondary_map.id.dst_port)
            return;
        is_tcp = 1;
    }
    else if(hdr.ip.protocol == UDP_PROTOCOL) {
        if(packet_len < sizeof(ethernet_t) + sizeof(update_t) + sizeof(ip_t) + sizeof(udp_t))
            return;
        if(hdr.udp.src_port != hdr.update.secondary_map.id.src_port
            || hdr.udp.dst_port != hdr.update.secondary_map.id.dst_port)
            return;
        is_tcp = 0;
    }
    else return;

    if(verify_checksum() != 0) return;

// allocate flow state for new flow
    update_t &update = hdr.update;
    auto ins = map.insert(make_pair(update.secondary_map.id, (map_val_t){0, 0}));
    auto it = ins.first;
    if(ins.second) {// a new flow
        if(free_port.empty()) return;// no port available, drop
        port_t eport = q.front();
        q.pop();

        it->second = (map_val_t){eport, ts};

        reverse_map[eport] = update.secondary_map.id;
    }

// refresh flow's timestamp
    it->second.ts = ts;

// translate
    checksum_t delta = 0;
    delta = add(delta, sub(NAT_ADDR & 0xffff, hdr.ip.src_addr & 0xffff));
    delta = add(delta, sub(NAT_ADDR >> 16, hdr.ip.src_addr >> 16));
    hdr.ip.src_addr = NAT_ADDR;
    // If the original checksum is wrong, the new one will also be wrong, 
    // and the packet will be droped by switch later.
    hdr.ip.checksum = make_zero_negative(sub(hdr.ip.checksum, delta));
    if(is_tcp) {
        delta = add(delta, sub(it->second.eport, hdr.L4_header.tcp.src_port));
        hdr.L4_header.tcp.src_port = it->second.eport;
        hdr.L4_header.tcp.checksum = make_zero_negative(sub(hdr.L4_header.tcp.checksum, delta));
    }
    else {
        delta = add(delta, sub(it->second.eport, hdr.L4_header.udp.src_port));
        hdr.L4_header.udp.src_port = it->second.eport;
        if(hdr.L4_header.udp.checksum != 0)
            hdr.L4_header.udp.checksum = make_zero_negative(sub(hdr.L4_header.udp.checksum, delta));
    }

// TODO*************************************
// choose whether to require a switch update (set hdr.update.type)

// send back
    pcap_sendpacket(device, (u_char *)hdr, packet_len);
}

void backward_process(mytime_t ts, len_t packet_len, backward_hdr_t * const hdr)
{
// verify
    if(packet_len < sizeof(ethernet_t) + sizeof(ip_t)) return;

    bool is_tcp;
    ip_addr_t src_addr = hdr.ip.src_addr;
    port_t eport, src_port;
    if(hdr.ip.protocol == TCP_PROTOCOL) {
        if(packet_len < sizeof(ethernet_t) + sizeof(ip_t) + sizeof(tcp_t))
            return;
        is_tcp = 1;
        eport = hdr.L4_header.tcp.dst_port;
        src_port = hdr.tcp.src_port;
    }
    else if(hdr.ip.protocol == UDP_PROTOCOL) {
        if(packet_len < sizeof(ethernet_t) + sizeof(ip_t) + sizeof(udp_t))
            return;
        is_tcp = 0;
        eport = hdr.L4_header.udp.dst_port;
        src_port = hdr.udp.src_port;
    }
    else return;

    if(eport <= PORT_MIN || eport >= PORT_MAX) return;

// match
    flow_id_t &flow_id = reverse_map[eport];
    if(flow_id.dst_addr != src_addr || flow_id.dst_port != src_port 
        || flow_id.protocol != hdr.ip.protocol)
        return; // drop on mismatch
    auto it = map.find(flow_id);
    if(it == map.end() || it->second.eport != eport || ts - it->second.timestamp > AGING_TIME_US)
        return; // drop on mismatch or aging

// refresh flow's timestamp
    it->second.ts = ts;

// tranlate
    checksum_t delta = 0;
    delta = add(delta, sub(flow_id.src_addr & 0xffff, hdr.ip.dst_addr & 0xffff));
    delta = add(delta, sub(flow_id.src_addr >> 16, hdr.ip.dst_addr >> 16));
    hdr.ip.dst_addr = flow_id.src_addr;
    hdr.ip.checksum = make_zero_negative(sub(hdr.ip.checksum, delta));
    if(is_tcp) {
        delta = add(delta, sub(flow_id.src_port, hdr.L4_header.tcp.dst_port));
        hdr.L4_header.tcp.dst_port = flow_id.src_port;
        hdr.L4_header.tcp.checksum = make_zero_negative(sub(hdr.L4_header.tcp.checksum, delta));
    }
    else {
        delta = add(delta, sub(flow_id.src_port, hdr.L4_header.udp.dst_port));
        hdr.L4_header.udp.dst_port = flow_id.src_port;
        if(hdr.L4_header.udp.checksum != 0)
            hdr.L4_header.udp.checksum = make_zero_negative(sub(hdr.L4_header.udp.checksum, delta));
    }

// send back
    pcap_sendpacket(device, (u_char *)hdr, packet_len);
}

void ack_process(mytime_t ts, len_t packet_len, forward_hdr_t * const hdr)
{

}

void nat_process(mytime_t ts, len_t packet_len, forward_hdr_t * const hdr)
{
    if(hdr.ethernet.ether_type == TYPE_UPDATE) {
        if(packet_len == sizeof(ethernet_t) + sizeof(update_t)) ack_process(ts, packet_len, hdr);
        else forward_process(ts, packet_len, hdr);
    }
    else if(hdr.ethernet.ether_type == TYPE_IPV4) backward_process(ts, packet_len, (backward_hdr_t * const) hdr)
}

void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
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
    device = pcap_open_live(dev_name, max_frame_size, 1, 0, errbuf);
    
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