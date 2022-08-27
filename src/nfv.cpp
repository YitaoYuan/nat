#include <cstdio>
#include <cstring>
#include <pcap/pcap.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <unordered_map>
#include <queue>
#include <cstdlib>
#include <arpa/inet.h>
#include "shared_metadata.h"

#ifdef DEBUG
#define debug_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug_printf(...)
#endif

using std::unordered_map;
using std::queue;
using std::make_pair;
using std::swap;

typedef unsigned short port_t;
typedef unsigned int ip_addr_t;
typedef unsigned int mytime_t;
typedef unsigned short len_t;
typedef unsigned short checksum_t;
typedef unsigned char version_t;
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

struct nat_metadata_t{
    flow_id_t   id;
    port_t      switch_port;
    version_t   version;
    u8          zero      : 5;
    u8          is_update : 1;
    u8          is_to_out : 1;
    u8          is_to_in  : 1;
    port_t      index;
    mytime_t    nfv_time_net;
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

struct hdr_t{
    ethernet_t ethernet;
    nat_metadata_t metadata;
    ip_t ip;
    L4_header_t L4_header;
};

enum list_type: u8{
    avail,
    inuse,
    sw
};

struct list_entry_t{
    flow_id_t id;// net
    port_t index_host;// host
    mytime_t timestamp_host;// host 
    list_type type;// host
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
    map_entry_t map;// net
    version_t version;// net
    port_t switch_port;// net
    mytime_t first_req_time_host, last_req_time_host;// host
    wait_entry_t *l, *r;
    bool is_waiting;
};



/*
 * All these constants are in host's byte order
 */

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
const u16 TYPE_METADATA = SHARED_TYPE_METADATA;

const u8 TCP_PROTOCOL = 0x06;
const u8 UDP_PROTOCOL = 0x11;

const u32 max_frame_size = 1514;

const u32 HEAVY_HITTER_SIZE = 8;
const u32 HEAVY_HITTER_REBOOT_THRESHOLD = 128;
/*
 * predefined MAC address is in network byte order
 */

static_assert(SHARED_SWITCH_INNER_MAC < 256u, "");
static_assert(SHARED_NFV_INNER_MAC < 256u, "");
const u8 SWITCH_INNER_MAC[6] = {0, 0, 0, 0, 0, SHARED_SWITCH_INNER_MAC};
const u8 NFV_INNER_MAC[6] = {0, 0, 0, 0, 0, SHARED_NFV_INNER_MAC};

pcap_t *device;

u8 buf[max_frame_size] __attribute__ ((aligned (64)));
u8 metadata_buf[sizeof(ethernet_t) + sizeof(nat_metadata_t)] __attribute__ ((aligned (64)));
/*
 * all bytes in these data structure are in network order
 */
unordered_map<flow_id_t, list_entry_t*, Hash>map;
list_entry_t reverse_map[PORT_MAX - PORT_MIN];
list_entry_t avail_port_leader_data, inuse_port_leader_data, sw_port_leader_data;
list_entry_t *avail_port_leader, *inuse_port_leader, *sw_port_leader;
//如果要追求通用性的话，reverse_map就应该用list而不是数组，map直接映射到iterator
//此时应该再开一个map映射eport到iterator

wait_entry_t wait_set[SWITCH_PORT_NUM];
wait_entry_t wait_set_leader_data;
wait_entry_t *wait_set_leader;

template<typename COUNTER_T, typename ID_T>
struct heavy_hitter_entry_t{
    COUNTER_T cnt;
    ID_T id;
};

template<typename COUNTER_T, typename ID_T>
struct heavy_hitter_t{
    heavy_hitter_entry_t<COUNTER_T, ID_T> entry[HEAVY_HITTER_SIZE];
    // entry[0].cnt is max, entry[HEAVY_HITTER_SIZE-1].cnt is min
    int size, total_cnt;
    void init() {
        size = 0;
        total_cnt = 0;
        memset(entry, 0, sizeof(entry));
    }
    void count(ID_T id) {
        if(total_cnt == HEAVY_HITTER_REBOOT_THRESHOLD) init();
        int i;
        for(i = 0; i < size; i++) if(entry[i].id == id) break;
        if(i >= size) {
            if(i == HEAVY_HITTER_SIZE) i--;
            else size++;
            entry[i].id = id;
        }
        entry[i].cnt++;
        total_cnt++;
        // re-sort
        for(i = i-1; i >= 0; i--) if(entry[i].cnt < entry[i+1].cnt) swap(entry[i], entry[i+1]);
    }
};

heavy_hitter_t<u16, port_t> heavy_hitter[SWITCH_PORT_NUM];

void stop(int signo)
{
    _exit(0);
}

template<typename T>
void list_erase(T *entry)
{
    entry->l->r = entry->r;
    entry->r->l = entry->l;
    entry->l = NULL;
    entry->r = NULL;
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

void print_map(flow_id_t id, port_t eport_host, port_t index)
{
    debug_printf("(src=%d.%d.%d.%d:%d, dst=%d.%d.%d.%d:%d, protocal=%d) -> (eport %d, index %d)\n", 
        ((u8*)&id.src_addr)[0],
        ((u8*)&id.src_addr)[1],
        ((u8*)&id.src_addr)[2],
        ((u8*)&id.src_addr)[3],
        ntohs(id.src_port),

        ((u8*)&id.dst_addr)[0],
        ((u8*)&id.dst_addr)[1],
        ((u8*)&id.dst_addr)[2],
        ((u8*)&id.dst_addr)[3],
        ntohs(id.dst_port),

        id.protocol,

        eport_host,
        index
    );
}

void nfv_init()
{
    avail_port_leader = &avail_port_leader_data;
    inuse_port_leader = &inuse_port_leader_data;
    sw_port_leader = &sw_port_leader_data;
    avail_port_leader->l = avail_port_leader->r = avail_port_leader;
    inuse_port_leader->l = inuse_port_leader->r = inuse_port_leader;
    sw_port_leader->l = sw_port_leader->r = sw_port_leader;
    
    for(port_t port = PORT_MIN; port < PORT_MIN + SWITCH_PORT_NUM; port++) {
        list_entry_t *entry = port_host_to_entry(port);
        entry->type = list_type::sw;
        list_insert_before(sw_port_leader, entry);
    }
        
    for(port_t port = PORT_MIN + SWITCH_PORT_NUM; port < PORT_MAX; port++) {
        list_entry_t *entry = port_host_to_entry(port);
        entry->type = list_type::avail;
        list_insert_before(avail_port_leader, entry);
    }

    wait_set_leader = &wait_set_leader_data;
    wait_set_leader->l = wait_set_leader->r = wait_set_leader;

    for(int i = 0; i < SWITCH_PORT_NUM; i++)
        heavy_hitter[i].init();
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

checksum_t compute_checksum(nat_metadata_t &hdr_metadata) {
    /*
    It is acceptable to only verify checksum of header "metadata"
    because we have aging mechanism.
    Wrong flow state will be removed by that.
    */
    checksum_t *l = (checksum_t *)&hdr_metadata;
    checksum_t *r = (checksum_t *)((u8*)&hdr_metadata + sizeof(nat_metadata_t));
    u32 res = 0;
    for(checksum_t *i = l; i < r; i++) 
        res += ntohs(*i);
    res = (res & 0xffff) + (res >> 16);
    res = (res & 0xffff) + (res >> 16);
    return ~(checksum_t)res;
}

void heavy_hitter_count(port_t bucket_index, port_t eport)
{
    heavy_hitter[bucket_index].count(eport);
}

port_t heavy_hitter_get(port_t bucket_index)
{
    auto &hh = heavy_hitter[bucket_index];
    for(int i = 0; i < hh.size; i++) {
        list_entry_t *entry = port_host_to_entry(hh.entry[i].id);
        if(entry->type == list_type::inuse && entry->index_host == bucket_index)
            return hh.entry[i].id;
        // if this has timeout, it will be locked and will not be moved to list "avail"
    }
    assert(false);
}

void send_back(hdr_t * hdr, size_t len)
{
    //debug_printf("send_back\n");
    memcpy(hdr->ethernet.dst_addr, SWITCH_INNER_MAC, sizeof(hdr->ethernet.dst_addr));
    memcpy(hdr->ethernet.src_addr, NFV_INNER_MAC, sizeof(hdr->ethernet.src_addr));
    pcap_sendpacket(device, (u_char *)hdr, len);
}

void send_update(port_t index)
{
    hdr_t *hdr = (hdr_t *)metadata_buf;
    // MAC address is useless between nfv & switch

    hdr->metadata.id = wait_set[index].map.id;
    hdr->metadata.switch_port = wait_set[index].map.eport;
    hdr->metadata.version = wait_set[index].version;

    hdr->metadata.zero = 0;
    hdr->metadata.is_update = 1;
    hdr->metadata.is_to_out = 0;
    hdr->metadata.is_to_in = 0;

    hdr->metadata.index = htons(index);

    hdr->metadata.nfv_time_net = htonl(wait_set[index].first_req_time_host);// not necessary to convert

    hdr->metadata.checksum = 0;// clear to recalculate
    hdr->metadata.checksum = make_zero_negative(htons(compute_checksum(hdr->metadata)));

    hdr->ethernet.ether_type = htons(TYPE_METADATA);
    send_back(hdr, sizeof(hdr->ethernet) + sizeof(hdr->metadata));

    debug_printf("\nsend update\n");
    //debug_printf("primary\n");
    //print_map(wait_set[index].primary_map.id, ntohs(wait_set[index].primary_map.eport), index);
    debug_printf("old switch port: %d\n", wait_set[index].switch_port);
    debug_printf("new map: ");
    print_map(wait_set[index].map.id, ntohs(wait_set[index].map.eport), index);
    debug_printf("version %u -> %u\n", wait_set[index].version - 1, wait_set[index].version);
}



void forward_process(mytime_t timestamp, len_t packet_len, hdr_t * hdr)
{
// verify
    // verify ip
    if(packet_len < sizeof(ethernet_t) + sizeof(nat_metadata_t) + sizeof(ip_t)) return;
    
    if(hdr->ip.src_addr != hdr->metadata.id.src_addr 
        || hdr->ip.dst_addr != hdr->metadata.id.dst_addr 
        || hdr->ip.protocol != hdr->metadata.id.protocol)
        return;
    // verify tcp/udp
    bool is_tcp;
    if(hdr->ip.protocol == TCP_PROTOCOL) {// 8 bit, OK
        if(packet_len < sizeof(ethernet_t) + sizeof(nat_metadata_t) + sizeof(ip_t) + sizeof(tcp_t))
            return;
        if(hdr->L4_header.tcp.src_port != hdr->metadata.id.src_port
            || hdr->L4_header.tcp.dst_port != hdr->metadata.id.dst_port)
            return;
        is_tcp = 1;
    }
    else if(hdr->ip.protocol == UDP_PROTOCOL) {
        if(packet_len < sizeof(ethernet_t) + sizeof(nat_metadata_t) + sizeof(ip_t) + sizeof(udp_t))
            return;
        if(hdr->L4_header.udp.src_port != hdr->metadata.id.src_port
            || hdr->L4_header.udp.dst_port != hdr->metadata.id.dst_port)
            return;
        is_tcp = 0;
    }
    else return;

// allocate flow state for new flow
    nat_metadata_t &metadata = hdr->metadata;
    // things in map are in network byte order
    auto it = map.find(metadata.id);
    if(it == map.end()) {// a new flow
        if(list_empty(avail_port_leader)) return;// no port available, drop
        list_entry_t *entry = list_front(avail_port_leader);
        
        entry->id = metadata.id;
        entry->index_host = ntohs(metadata.index);
        entry->type = list_type::inuse;
        entry->is_waiting = 0;
        list_move_to_back(inuse_port_leader, entry);

        it = map.insert(make_pair(metadata.id, entry)).first;
    }
// refresh flow's timestamp
    list_entry_t *entry = it->second;
    port_t eport_h = entry_to_port_host(entry);
    port_t eport_n = htons(eport_h);
    entry->timestamp_host = timestamp;// host

    assert(entry->type == list_type::inuse);
    list_move_to_back(inuse_port_leader, entry);

// heavy hitter detect
    port_t index = entry->index_host;
    heavy_hitter_count(index, entry_to_port_host(entry));

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

// fill hdr
    //metadata.secondary_map.eport = eport_n;
    //delta = eport_h;
// require to update switch's mapping

    if(metadata.is_update) {//
        if(!wait_set[index].is_waiting) {
            port_t swap_port_h = heavy_hitter_get(index);
            port_t swap_port_n = htons(swap_port_h);
            list_entry_t *swap_entry = port_host_to_entry(swap_port_h);
            flow_id_t &swap_id = swap_entry->id;

            wait_set[index] = {{swap_id, swap_port_n}, (u8)(metadata.version + 1), 
                                metadata.switch_port, timestamp, timestamp, NULL, NULL, true};
            // map entry
            swap_entry->is_waiting = 1;// locked, it will not be moved to list "avail" immediately

            list_insert_before(wait_set_leader, &wait_set[index]);// == push_back
            send_update(index);
        }
        //clear this bit, 因为在返回的包中is_update和is_to_in/out最多只有一个为1
        metadata.is_update = 0;
        delta = sub(0x0000, 0x0020);
        metadata.checksum = htons(make_zero_negative(sub(ntohs(metadata.checksum), delta)));
    }
    

// send back
send:
    send_back(hdr, packet_len);
}

void backward_process(mytime_t timestamp, len_t packet_len, hdr_t * const hdr)
{
    /*
     * 注意，对于反向的包，其metadata部分只有id和is_to_in/out是可用的，其余都是0
     */

// verify
    if(packet_len < sizeof(ethernet_t) + sizeof(nat_metadata_t) + sizeof(ip_t)) return;

    bool is_tcp;
    ip_addr_t src_addr = hdr->ip.src_addr;
    port_t eport_n, src_port;
    if(hdr->ip.protocol == TCP_PROTOCOL) {// 8 bit, OK
        if(packet_len < sizeof(ethernet_t) + sizeof(nat_metadata_t) + sizeof(ip_t) + sizeof(tcp_t))
            return;
        is_tcp = 1;
        eport_n = hdr->L4_header.tcp.dst_port;
        src_port = hdr->L4_header.tcp.src_port;
    }
    else if(hdr->ip.protocol == UDP_PROTOCOL) {
        if(packet_len < sizeof(ethernet_t) + sizeof(nat_metadata_t) + sizeof(ip_t) + sizeof(udp_t))
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

// heavy hitter detect
    port_t index = entry->index_host;
    heavy_hitter_count(index, entry_to_port_host(entry));

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
    send_back(hdr, packet_len);
}

void ack_process(mytime_t timestamp, len_t packet_len, hdr_t * hdr)
{
    //debug_printf("receive ACK\n");
    // only hdr.ethernet & hdr.metadata is valid
    assert(hdr->metadata.is_update);
    
    if(timestamp - ntohl(hdr->metadata.nfv_time_net) > AGING_TIME_US / 2) return;
    //debug_printf("1\n");
    port_t index = ntohs(hdr->metadata.index);
    if(index >= SWITCH_PORT_NUM) return; // if checksum is right, this could not happen
    //debug_printf("2\n");
    wait_entry_t *wait_entry = &wait_set[index];
    if(!wait_entry -> is_waiting) return; // Redundant ACK
    //debug_printf("3\n");
    // mismatch
    if(memcmp(&wait_entry->map.id, &hdr->metadata.id, sizeof(hdr->metadata.id)) != 0 ||
        wait_entry->map.eport != hdr->metadata.switch_port ||
        wait_entry->version != hdr->metadata.version) 
        return;
    //debug_printf("4\n");
    list_entry_t *entry_sw = port_host_to_entry(ntohs(wait_entry->switch_port));
    list_entry_t *entry_nfv = port_host_to_entry(ntohs(wait_entry->map.eport));

    assert(entry_sw->type == list_type::sw && entry_nfv->type == list_type::inuse);

    entry_sw->is_waiting = 0;// this assignment is useless
    entry_nfv->is_waiting = 0;
    wait_entry->is_waiting = 0;

    entry_sw->type = list_type::avail;
    entry_nfv->type = list_type::sw;

    list_move_to_back(avail_port_leader, entry_sw);// sw->avail
    list_move_to_back(sw_port_leader, entry_nfv);// inuse->sw
    list_erase(wait_entry);

    debug_printf("\nreceive ACK\n");
    debug_printf("old switch port: %d\n", wait_set[index].switch_port);
    debug_printf("new map: ");
    print_map(wait_set[index].map.id, ntohs(wait_set[index].map.eport), index);
    debug_printf("version %u -> %u\n", wait_set[index].version - 1, wait_set[index].version);
}

void do_aging(mytime_t timestamp)
{
    for(list_entry_t *entry = inuse_port_leader->r, *nxt; 
        entry != inuse_port_leader; entry = nxt) {
        
        nxt = entry->r;// must first calculate address nxt, or SGfault may happen 

        if(timestamp - entry->timestamp_host <= AGING_TIME_US) break;

        if(entry->is_waiting) continue;// wait to swap to switch

        list_move_to_back(avail_port_leader, entry);
        entry->type = list_type::avail;
        auto erase_res = map.erase(entry->id);
        assert(erase_res == 1); 
    }
    // for debug
    static mytime_t last_timestamp = 0;
    if(timestamp - last_timestamp < 200000) return;
    last_timestamp = timestamp;    


    debug_printf("\n");
    list_entry_t *entry = list_front(inuse_port_leader);
    int cnt = 0;
    while(entry != inuse_port_leader) {
        flow_id_t id = entry->id;
        port_t index = entry->index_host;
        port_t eport = entry_to_port_host(entry);
        print_map(id, eport, index);
        cnt++;
        entry = entry->r;
    }
    debug_printf("%d active flows\n", cnt);
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
        if(timestamp - entry->last_req_time_host <= WAIT_TIME_US) break;
        if(timestamp - entry->first_req_time_host > AGING_TIME_US / 2) report_wait_time_too_long();
        entry->last_req_time_host = timestamp;

        port_t index = (port_t)(entry - wait_set);
        send_update(index);
        list_move_to_back(wait_set_leader, entry);
    }
}

void nat_process(mytime_t timestamp, len_t packet_len, hdr_t * hdr)
{
    do_aging(timestamp);
    if(memcmp(hdr->ethernet.src_addr, SWITCH_INNER_MAC, sizeof(hdr->ethernet.src_addr)) != 0 ||
        memcmp(hdr->ethernet.dst_addr, NFV_INNER_MAC, sizeof(hdr->ethernet.dst_addr)) != 0)
        return;
    if(hdr->ethernet.ether_type != htons(TYPE_METADATA)) 
        return;

    if(packet_len < sizeof(ethernet_t) + sizeof(nat_metadata_t)) 
        return;
    // only check checksum of header update
    if(compute_checksum(hdr->metadata) != 0) return;

    if(hdr->metadata.is_update && !hdr->metadata.is_to_in && !hdr->metadata.is_to_out)
        ack_process(timestamp, packet_len, hdr);
    else if(hdr->metadata.is_to_out && !hdr->metadata.is_to_in) 
        forward_process(timestamp, packet_len, hdr);
    else if(hdr->metadata.is_to_in && !hdr->metadata.is_to_out) 
        backward_process(timestamp, packet_len, (hdr_t *) hdr);
}

void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    //h->ts.tv_sec/tv_usec
    //h->caplen
    //h->len
    if(h->caplen != h->len) return;
    if(h->len < sizeof(ethernet_t)) return;
    memcpy(buf, bytes, h->len);

    timespec tm;
    clock_gettime(CLOCK_MONOTONIC, &tm); // don't use pcap's clock

    nat_process(tm.tv_sec * 1000000ull + tm.tv_nsec / 1000, h->len, (hdr_t*)buf);
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

        timespec tm;
        clock_gettime(CLOCK_MONOTONIC, &tm);

        update_wait_set(tm.tv_sec * 1000000ull + tm.tv_nsec / 1000);
    }
    return 0;
}
