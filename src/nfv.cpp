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
    accept_update = 0x0300
    //reject_update = 0x0400//看上去reject是不需要的？？？如果checksum failed直接drop不就好了？
};

struct update_t{
    map_entry_t primary_map; 
    map_entry_t secondary_map;
    message_t type;
    port_t index;
    mytime_t sw_time;
    mytime_t nfv_time;
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

enum list_type: u8{
    free,
    inuse,
    sw
};

struct list_entry_t{
    flow_id_t id;
    mytime_t timestamp_host;// only this is in host order
    list_type type;
    bool is_waiting;
    list_entry_t *l, *r;
};

struct Hash{
    size_t operator ()(const flow_id_t &id) const{
        return (u64)id.src_addr ^ (u64)id.dst_addr << 32 ^ 
            (u64)id.src_port ^ (u64)id.dst_port << 16 ^ (u64)id.protocol << 32;
    }
};

struct wait_entry_t{
    map_entry_t primary_map, secondary_map;
    mytime_t sw_time, first_req_time, last_req_time;
    wait_entry_t *l, *r;
    bool is_waiting;
};


/*
 * All these constants are in host's byte order
 */
const u16 TYPE_UPDATE = SHARED_TYPE_UPDATE;

const ip_addr_t LAN_ADDR_START = SHARED_LAN_ADDR_START;
const ip_addr_t LAN_ADDR_END = SHARED_LAN_ADDR_END;// not included
const ip_addr_t NAT_ADDR = SHARED_NAT_ADDR;

const port_t PORT_MIN = SHARED_PORT_MIN;
const u32 PORT_MAX = SHARED_PORT_MAX;// not included
const port_t SWITCH_PORT_NUM = SHARED_SWITCH_PORT_NUM;
const port_t NFV_PORT_NUM = PORT_MAX - PORT_MIN - SWITCH_PORT_NUM;

const u32 AGING_TIME_US = SHARED_AGING_TIME_US;
const u32 WAIT_TIME_US = 10000;// 10 ms

const u16 TYPE_IPV4 = 0x800;
const u16 TYPE_UPDATE = 0x88B5;

const u8 TCP_PROTOCOL = 0x06;
const u8 UDP_PROTOCOL = 0x11;

const u32 max_frame_size = 1514;

pcap_t *device;

u8 buf[max_frame_size] __attribute__ ((aligned (64)));
u8 update_buf[sizeof(ethernet_t) + sizeof(update_t)] __attribute__ ((aligned (64)));
/*
 * all bytes in these data structure are in network order
 */
unordered_map<flow_id_t, list_entry_t*, Hash>map;
list_entry_t reverse_map[PORT_MAX - PORT_MIN];
list_entry_t free_port_leader_data, inuse_port_leader_data, sw_port_leader_data;
list_entry_t *free_port_leader, *inuse_port_leader, *sw_port_leader;
//如果要追求通用性的话，reverse_map就应该用list而不是数组，map直接映射到iterator
//此时应该再开一个map映射eport到iterator

wait_entry_t wait_set[SWITCH_PORT_NUM];
wait_entry_t wait_set_leader_data;
wait_entry_t *wait_set_leader;


unordered_map<port_t, wait_time_t>wait_port;

void stop(int signo)
{
    _exit(0);
}

template<typename T>
void list_erase(T *entry)
{
    entry->l->r = entry->r;
    entry->r->l = entry->l;
}

template<typename T>
void list_insert_before(T *r, T *entry)
{
    T *l = r->l;
    l->r = entry;
    r->l = entry;
    entry->l = l;
    entry->r = r;
}

template<typename T>
void list_move_to(T *r, T *entry)
{
    list_erase(entry);
    list_insert_before(r, entry);
}

template<typename T>
void list_move_to_back(T *leader, T *entry)
{
    list_move_to(leader, entry);
}

template<typename T>
void list_move_to_front(T *leader, T *entry)
{
    list_move_to(leader->r, entry);
}

template<typename T>
T *list_front(T *leader)
{
    return leader->r;
}

template<typename T>
bool list_empty(T *leader)
{
    return leader->l == leader;
}

port_t entry_to_port_host(list_entry_t *entry)
{
    return (port_t)(entry - reverse_map) + PORT_MIN;
}

list_entry_t *port_host_to_entry(port_t port)
{
    return &reverse_map[port - PORT_MIN];
}

void nfv_init()
{
    free_port_leader = &free_port_leader_data;
    inuse_port_leader = &inuse_port_leader_data;
    sw_port_leader = &sw_port_leader_data;
    free_port_leader->l = free_port_leader->r = free_port_leader;
    inuse_port_leader->l = inuse_port_leader->r = inuse_port_leader;
    sw_port_leader->l = sw_port_leader->r = sw_port_leader;
    
    for(port_t port = PORT_MIN; port < PORT_MIN + SWITCH_PORT_NUM; port++) {
        list_entry_t *entry = port_host_to_entry(port);
        entry->type = list_type::sw;
        list_insert_before(sw_port_leader, entry);
    }
        
    for(port_t port = PORT_MIN + SWITCH_PORT_NUM; port < PORT_MAX; port++) {
        list_entry_t *entry = port_host_to_entry(port);
        entry->type = list_type::free;
        list_insert_before(free_port_leader, entry);
    }

    wait_set_leader = &wait_set_leader_data;
    wait_set_leader->l = wait_set_leader->r = wait_set_leader;
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

checksum_t compute_checksum(update_t &hdr_update) {
    /*
    It is acceptable to only verify checksum of header "update"
    because we have aging mechanism.
    Wrong flow state will be removed by that.
    */
    checksum_t *l = (checksum_t *)&hdr_update;
    checksum_t *r = (checksum_t *)((u8*)&hdr_update + sizeof(update_t));
    u32 res = 0;
    for(checksum_t *i = l; i < r; i++) res += ntohs(*i);
    res = (res & 0xffff) + (res >> 16);
    res = (res & 0xffff) + (res >> 16);
    checksum_t chsum = ~(checksum_t)res;
    return make_zero_negative(chsum);
}

void send_update(port_t index)
{
    forward_hdr_t *hdr = (forward_hdr_t *)update_buf;
    // MAC address is useless between nfv & switch
    memset(hdr->ethernet.dst_addr, -1, sizeof(hdr->ethernet.dst_addr));
    memset(hdr->ethernet.src_addr, -1, sizeof(hdr->ethernet.src_addr));
    hdr->ethernet.ether_type = TYPE_UPDATE;

    hdr->update.primary_map = wait_set[index].primary_map;
    hdr->update.secondary_map = wait_set[index].secondary_map;

    hdr->update.type = message_t::require_update;
    hdr->update.index = index;

    hdr->update.sw_time = wait_set[index].sw_time;
    hdr->update.nfv_time = wait_set[index].first_req_time;

    hdr->update.checksum = 0;// clear to recalculate
    hdr->update.checksum = compute_checksum(hdr->update);

    pcap_sendpacket(device, (u_char *)hdr, sizeof(hdr->ethernet) + sizeof(hdr->update));
}

void forward_process(mytime_t timestamp, len_t packet_len, forward_hdr_t * const hdr)
{
// verify
    if(packet_len < sizeof(ethernet_t) + sizeof(update_t) + sizeof(ip_t)) return;
    // verify update
    if(hdr.update.type != message_t::null && hdr.update.type != message_t::timeout) return;
    // verify ip
    if(hdr->ip.src_addr != hdr->update.secondary_map.id.src_addr 
        || hdr->ip.dst_addr != hdr->update.secondary_map.id.dst_addr 
        || hdr->ip.protocol != hdr->update.secondary_map.id.protocol)
        return;
    // verify tcp/udp
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

// allocate flow state for new flow
    update_t &update = hdr->update;
    // things in map are in network byte order
    auto it = map.find(update.secondary_map.id);
    if(it == map.end()) {// a new flow
        if(list_empty(free_port_leader)) return;// no port available, drop
        list_entry_t *entry = list_front(free_port_leader);
        
        entry->id = update.secondary_map.id;
        entry->type = list_type::inuse;
        entry->is_waiting = 0;
        list_move_to_back(inuse_port_leader, entry);

        it = map.insert(make_pair(update.secondary_map.id, entry)).first;
    }
// refresh flow's timestamp
    list_entry_t *entry = it->second;
    port_t eport_h = entry_to_port_host(entry);
    port_t eport_n = htons(eport_h);
    entry->timestamp_host = timestamp;// host

    assert(entry->type == list_type::inuse);
    list_move_to_back(inuse_port_leader, entry);

// translate
    checksum_t delta = 0;// host
    delta = add(delta, sub(NAT_ADDR >> 16, ntohs(hdr->ip.src_addr & 0xffff)));
    delta = add(delta, sub(NAT_ADDR & 0xffff, ntohs(hdr->ip.src_addr >> 16)));
    hdr->ip.src_addr = htonl(NAT_ADDR);
    // If the original checksum is wrong, the new one will also be wrong, 
    // and the packet will be droped by switch later.
    hdr->ip.checksum = htons(make_zero_negative(sub(ntohs(hdr->ip.checksum), delta)));
    if(is_tcp) {
        delta = add(delta, sub(eport_h, ntohs(hdr->L4_header.tcp.src_port)));
        hdr->L4_header.tcp.src_port = eport_n;// 
        hdr->L4_header.tcp.checksum = htons(make_zero_negative(sub(ntohs(hdr->L4_header.tcp.checksum), delta)));
    }
    else {
        delta = add(delta, sub(eport_h, ntohs(hdr->L4_header.udp.src_port)));
        hdr->L4_header.udp.src_port = eport_n;
        if(hdr->L4_header.udp.checksum != 0)// 0 is same for n & h
            hdr->L4_header.udp.checksum = htons(make_zero_negative(sub(ntohs(hdr->L4_header.udp.checksum), delta)));
    }

// require to update switch's mapping

    if(hdr->update.type == message_t::timeout) {
        hdr->update.secondary_map.eport = eport_n;
        port_t index = hdr->update.index;
        if(wait_set[index].is_waiting) goto send:

        wait_set[index] = {hdr->update.primary_map, hdr->update.secondary_map, 
                            hdr->update.sw_time, timestamp, timestamp, NULL, NULL, true};
        // map entry
        entry->is_waiting = 1;

        list_insert_before(wait_set_leader, &wait_set[index]);// == push_back
        send_update(index);
    }

// send back
send:
    // delete header update
    hdr.ethernet.type = TYPE_IPV4;
    u8 *new_hdr = (u8*)hdr + sizeof(update);
    memcpy(new_hdr, (u8*)hdr, sizeof(hdr.ethernet));
    pcap_sendpacket(device, (u_char *)new_hdr, packet_len);
}

void backward_process(mytime_t timestamp, len_t packet_len, backward_hdr_t * const hdr)
{
// verify
    if(packet_len < sizeof(ethernet_t) + sizeof(ip_t)) return;

    bool is_tcp;
    ip_addr_t src_addr = hdr->ip.src_addr;
    port_t eport_n, src_port;
    if(hdr->ip.protocol == TCP_PROTOCOL) {// 8 bit, OK
        if(packet_len < sizeof(ethernet_t) + sizeof(ip_t) + sizeof(tcp_t))
            return;
        is_tcp = 1;
        eport_n = hdr->L4_header.tcp.dst_port;
        src_port = hdr->L4_header.tcp.src_port;
    }
    else if(hdr->ip.protocol == UDP_PROTOCOL) {
        if(packet_len < sizeof(ethernet_t) + sizeof(ip_t) + sizeof(udp_t))
            return;
        is_tcp = 0;
        eport_n = hdr->L4_header.udp.dst_port;
        src_port = hdr->L4_header.udp.src_port;
    }
    else return;
    port_t eport_h = ntohs(eport_n);

    if(eport_h <= PORT_MIN || eport_h >= PORT_MAX) return;

    list_entry_t *entry = port_host_to_entry(eport_h);
    if(entry->type != list_type::inuse) return;

// match
    flow_id_t &flow_id = entry->id;
    if(flow_id.dst_addr != src_addr || flow_id.dst_port != src_port 
        || flow_id.protocol != hdr->ip.protocol)
        return; // drop on mismatch
    auto it = map.find(flow_id);
    assert(it != map.end() && it->second == entry);// because it is in use
    
// refresh flow's timestamp
    entry->timestamp_host = timestamp;
    list_move_to_back(inuse_port_leader, entry);

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
    // only hdr.ethernet & hdr.update is valid
    assert(hdr->update.type == message_t::accept_update || hdr->update.type == message_t::reject_update);
    
    if(timestamp - hdr.update.nfv_time > AGING_TIME_US / 2) return;
    if(hdr.update.index >= SWITCH_PORT_NUM) return; // if checksum is right, this could not happen

    wait_entry_t *wait_entry = &wait_set[hdr.update.index];
    if(!wait_entry -> is_waiting) return; // Redundant ACK
    
    if(wait_entry->primary_map != hdr->update.primary_map ||
        wait_entry->secondary_map != hdr->update.secondary_map) // mismatch
        return;

    list_entry_t *entry_sw = port_host_to_entry(ntohs(hdr->update.primary_map.eport));
    list_entry_t *entry_nfv = port_host_to_entry(ntohs(hdr->update.secondary_map.eport));
    
    assert(entry_sw->type == list_type::sw && entry_nfv->type == list_type::inuse);

    entry_sw->is_waiting = 0;// this assignment is useless
    entry_nfv->is_waiting = 0;
    wait_entry->is_waiting = 0;

    entry_sw->type = list_type::free;
    entry_nfv->type = list_type::sw;

    list_move_to_back(free_port_leader, entry_sw);// sw->free
    list_move_to_back(sw_port_leader, entry_nfv);// inuse->sw
    list_erase(wait_entry);
}

void do_aging(mytime_t timestamp)
{
    while(!list_empty(inuse_port_leader)) {
        list_entry_t *entry = list_front(inuse_port_leader);
        if(timestamp - entry->timestamp_host <= AGING_TIME_US) break;

        if(entry->is_waiting) continue;// wait to swap to switch

        list_move_to_back(free_port_leader, entry);
        entry->type = list_type::free;
        auto erase_res = map.erase(entry->id);
        assert(erase_res == 1); 
    }
    list_entry_t *entry = list_front(inuse_port_leader);
    int cnt = 0;
    while(entry != inuse_port_leader) cnt++, entry = entry->r;
    printf("%d active flows\n", cnt);
}

void report_wait_time_too_long()
{
    fprintf(stderr, "Wait time too long!");
    exit(0);
}

void update_wait_set(mytime_t timestamp)
{
    while(!list_empty(wait_set_leader))
    {
        wait_entry_t *entry = list_front(wait_set_leader);
        if(timestamp - entry->last_req_time <= WAIT_TIME_US) break;
        if(timestamp - entry->first_req_time > AGING_TIME_US / 2) report_wait_time_too_long();
        entry->last_req_time = timestamp;

        port_t index = (port_t)(entry - wait_set);
        send_update(index);
        list_move_to_back(wait_set_leader, entry);
    }
}

void nat_process(mytime_t timestamp, len_t packet_len, forward_hdr_t * hdr)
{
    do_aging(timestamp);
    if(hdr->ethernet.ether_type == htons(TYPE_UPDATE)) {
        if(packet_len < sizeof(ethernet_t) + sizeof(update_t)) return;

        // only check checksum of header update
        if(compute_checksum(hdr->update) != 0) return;

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
    //fprintf(stderr, "a packet\n");
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

    pcap_setnonblock(device, 1, errbuf);
    while(1) {
        pcap_dispatch(device, 4, pcap_handle, NULL);// process at most 4 packets
        update_wait_set();
    }
    return 0;
}
