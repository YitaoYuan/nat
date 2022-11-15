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
#include "type.h"
#include "hdr.h"

#include "hash.cpp"
#include "list.cpp"
#include "checksum.cpp"
#include "heavy_hitter.cpp"

#ifdef DEBUG
#define debug_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug_printf(...)
#endif

using std::unordered_map;
using std::queue;
using std::make_pair;
using std::swap;


/*
 * All these constants are in host's byte order
 */
const flow_num_t SWITCH_FLOW_NUM = SHARED_SWITCH_FLOW_NUM;
const flow_num_t TOTAL_FLOW_NUM = SHARED_TOTAL_FLOW_NUM;

const host_time_t AGING_TIME_US = SHARED_AGING_TIME_US;
const host_time_t WAIT_TIME_US = 10000;// 10 ms

const u16 TYPE_IPV4 = 0x800;
const u16 TYPE_METADATA = SHARED_TYPE_METADATA;

const u8 TCP_PROTOCOL = 0x06;
const u8 UDP_PROTOCOL = 0x11;

const u32 MAX_FRAME_SIZE = 1514;
const size_t PACKET_WITH_META_LEN = sizeof(ethernet_t) + sizeof(nat_metadata_t);
const size_t MIN_UDP_LEN = PACKET_WITH_META_LEN + sizeof(ip_t) + sizeof(udp_t);
const size_t MIN_TCP_LEN = PACKET_WITH_META_LEN + sizeof(ip_t) + sizeof(tcp_t);

const u32 MAX_BORROW_RETRY = 3;

enum list_type: u8{
    avail = 0,
    inuse = 1,
    sw = 2
};

struct flow_entry_t{
    map_entry_t map;// net
    flow_num_t val_index_host;
    flow_num_t id_index_host;// host
    host_time_t timestamp_host;// host 
    list_type type;// host
    bool is_waiting;
    flow_entry_t *l, *r;
};

struct wait_entry_t{
    flow_entry_t *new_flow;
    flow_entry_t *old_flow;// we don't care old_flow->id
    version_t version;// net (u8 is the same)
    switch_time_t switch_time;// net
    host_time_t first_req_time_host;
    host_time_t last_req_time_host;// host
    bool is_waiting;
    wait_entry_t *l, *r;
};

template<typename T>
flow_num_t get_index(const T &data)
{
    my_hash<T> hasher;
    return hasher(data) % SWITCH_FLOW_NUM;
}


/*
 * predefined MAC address is in network byte order
 */
struct MAC_pair{
    u16 hi;
    u32 lo;
}__attribute__ ((__packed__));

static_assert(sizeof(MAC_pair) == 6);

MAC_pair SWITCH_INNER_MAC_PAIR = {htons(SHARED_SWITCH_INNER_MAC_HI16), htonl(SHARED_SWITCH_INNER_MAC_LO32)};
MAC_pair NF_INNER_MAC_PAIR = {htons(SHARED_NF_INNER_MAC_HI16), htonl(SHARED_NF_INNER_MAC_LO32)};

const u8 *SWITCH_INNER_MAC = (u8 *) &SWITCH_INNER_MAC_PAIR;
const u8 *NF_INNER_MAC = (u8 *) &NF_INNER_MAC_PAIR;


pcap_t *device;
// for regular packet
u8 buf[MAX_FRAME_SIZE] __attribute__ ((aligned (64)));
// for updating message
u8 metadata_buf[sizeof(ethernet_t) + sizeof(nat_metadata_t)] __attribute__ ((aligned (64)));
/*
 * all bytes in these data structure are in network order
 */
unordered_map<flow_id_t, flow_entry_t*, my_hash<flow_id_t>, mem_equal<flow_id_t> >id_map;
unordered_map<flow_val_t, flow_entry_t*, my_hash<flow_val_t>, mem_equal<flow_val_t> >val_map;

flow_entry_t inuse_head, sw_head, avail_head[SWITCH_FLOW_NUM];
flow_entry_t flow_entry[TOTAL_FLOW_NUM];

wait_entry_t wait_set[SWITCH_FLOW_NUM];
wait_entry_t wait_set_head;

heavy_hitter_t<u8, flow_entry_t*, 8, 128> heavy_hitter[SWITCH_FLOW_NUM];

void heavy_hitter_count(flow_num_t id_index, flow_entry_t* entry)
{
    heavy_hitter[id_index].count(entry);
}

flow_entry_t* heavy_hitter_get(flow_num_t id_index)
{
    auto &hh = heavy_hitter[id_index];
    for(int i = 0; i < hh.size; i++) {
        flow_entry_t *entry = hh.entry[i].id;
        if(entry->type == list_type::inuse && entry->id_index_host == id_index)
            return hh.entry[i].id;
        // if this has timeout, it will be locked and will not be moved to list "avail"
    }
    return NULL;
}


void stop(int signo)
{
    _exit(0);
}

void print_map(flow_id_t id, flow_val_t val, flow_num_t index)
{
    debug_printf("(src=%d.%d.%d.%d:%d, dst=%d.%d.%d.%d:%d, protocal=%d) -> (%d.%d.%d.%d:%d, index %d)\n", 
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

        ((u8*)&val.wan_addr)[0],
        ((u8*)&val.wan_addr)[1],
        ((u8*)&val.wan_addr)[2],
        ((u8*)&val.wan_addr)[3],
        val.wan_port,
        
        index
    );
}

void nf_init()
{       
    crc_initialize();

    inuse_head.l = inuse_head.r = &inuse_head;
    sw_head.l = sw_head.r = &sw_head;

    for(flow_num_t i = 0; i < SWITCH_FLOW_NUM; i++) {
        avail_head[i].l = avail_head[i].r = &avail_head[i];
    }

    ip_addr_t wan_addr_base = 0xC0A802FE;
    port_t port_min = (1<<15);
    flow_num_t port_num_per_addr = (1<<16) - port_min;

    for(flow_num_t i = 0; i < TOTAL_FLOW_NUM; i++) {// BUG fixed !! don't use "port <= PORT_MAX"
        ip_addr_t addr_offset = i / port_num_per_addr;
        ip_addr_t wan_addr = wan_addr_base - addr_offset;
        port_t wan_port = port_min + i % port_num_per_addr;

        flow_entry_t &entry = flow_entry[i];
        entry.map.val = {htonl(wan_addr), htons(wan_port)};
        entry.val_index_host = get_index(entry.map.val);
        entry.type = list_type::avail;
        entry.is_waiting = 0;
        
        list_insert_before(&avail_head[entry.val_index_host], &entry);

        val_map.insert(make_pair(entry.map.val, &entry));
    }

    wait_set_head.l = wait_set_head.r = &wait_set_head;

    for(flow_num_t i = 0; i < SWITCH_FLOW_NUM; i++)
        heavy_hitter[i].init();
}

void send_back(hdr_t * hdr, size_t len)
{
    //debug_printf("send_back\n");
    memcpy(hdr->ethernet.dst_addr, SWITCH_INNER_MAC, sizeof(hdr->ethernet.dst_addr));
    memcpy(hdr->ethernet.src_addr, NF_INNER_MAC, sizeof(hdr->ethernet.src_addr));
    pcap_sendpacket(device, (u_char *)hdr, len);
}

void send_update(flow_num_t index, bool force_update)
{
    hdr_t *hdr = (hdr_t *)metadata_buf;
    // MAC address is useless between nf & switch

    hdr->metadata.map = wait_set[index].new_flow->map;
    hdr->metadata.version = wait_set[index].version;

    hdr->metadata.update = force_update;
    hdr->metadata.type = 6;

    hdr->metadata.index = htonl(index);

    hdr->metadata.switch_time = wait_set[index].switch_time;// not necessary to convert

    hdr->metadata.checksum = 0;// clear to recalculate

    net_checksum_calculator sum;
    sum.add(&hdr->metadata, sizeof(hdr->metadata));
    
    hdr->metadata.checksum = sum.checksum();

    hdr->ethernet.ether_type = htons(TYPE_METADATA);
    send_back(hdr, sizeof(hdr->ethernet) + sizeof(hdr->metadata));

    debug_printf("\nsend update\n");
    //debug_printf("primary\n");
    //print_map(wait_set[index].primary_map.id, ntohs(wait_set[index].primary_map.eport), index);
    debug_printf("old map:\n");
    print_map((flow_id_t){0,0,0,0,0,0}, wait_set[index].old_flow->map.val, index);
    debug_printf("new map:\n");
    print_map(wait_set[index].new_flow->map.id, wait_set[index].new_flow->map.val, index);
    
    debug_printf("version %u -> %u\n", wait_set[index].version - 1, wait_set[index].version);
}

void try_add_update(flow_num_t wait_set_index, nat_metadata_t &metadata, host_time_t timestamp)
{
    if(!wait_set[wait_set_index].is_waiting) {
        flow_entry_t *new_entry = heavy_hitter_get(wait_set_index);

        if(new_entry == NULL) {
            return;
        }

        assert(metadata.map.val.wan_port != 0);//If we have preload process, this is always true.

        auto val_map_it = val_map.find({metadata.map.val.wan_addr, metadata.map.val.wan_port});
        assert(val_map_it != val_map.end());

        flow_entry_t *old_entry = val_map_it->second;
        assert(old_entry->type == list_type::sw);

        wait_set[wait_set_index] = {new_entry, old_entry, (u8)(metadata.version + 1), 
                                    metadata.switch_time, timestamp, timestamp, 
                                    true, NULL, NULL};
            
        // map entry
        new_entry->is_waiting = 1;// locked, it will not be moved to list "avail" immediately

        list_insert_before(&wait_set_head, &wait_set[wait_set_index]);// == push_back
        send_update(wait_set_index, 0);
    }
}

void forward_process(host_time_t timestamp, len_t packet_len, hdr_t * hdr)
{
// verify
    nat_metadata_t &metadata = hdr->metadata;
    
    bool is_tcp = metadata.map.id.protocol == TCP_PROTOCOL;
    if((is_tcp && packet_len < MIN_TCP_LEN) || (!is_tcp && packet_len < MIN_UDP_LEN))
        return;

// allocate flow state for new flow
    
    // things in map are in network byte order
    auto id_map_it = id_map.find(metadata.map.id);
    if(id_map_it == id_map.end()) {// a new flow
        flow_num_t id_index_host = get_index(metadata.map.id);
        assert(id_index_host == ntohl(metadata.index));

        flow_num_t index_select = id_index_host;
        
        u32 retry = 0;
        while(list_empty(&avail_head[index_select])) {
            retry ++;
            if(retry > MAX_BORROW_RETRY) break;
            index_select = (flow_num_t)(rand() ^ (rand() << 16)) % SWITCH_FLOW_NUM;
        }

        if(list_empty(&avail_head[index_select])) return;// too full to allocate, drop

        flow_entry_t *entry = list_front(&avail_head[index_select]);
        
        entry->map.id = metadata.map.id;
        entry->id_index_host = id_index_host;
        entry->type = list_type::inuse;
        entry->is_waiting = 0;
        list_move_to_back(&inuse_head, entry);

        id_map_it = id_map.insert(make_pair(metadata.map.id, entry)).first;
    }
// refresh flow's timestamp
    flow_entry_t *entry = id_map_it->second;
    entry->timestamp_host = timestamp;// host

    assert(entry->type == list_type::inuse);
    list_move_to_back(&inuse_head, entry);

// heavy hitter detect
    if(entry->id_index_host == entry->val_index_host) {
        // it is not a borrowed entry
        heavy_hitter_count(entry->val_index_host, entry);
    }
    

// translate
    net_checksum_calculator sum;

    sum.sub(&hdr->ip.src_addr, 4);
    hdr->ip.src_addr = entry->map.val.wan_addr;
    sum.add(&hdr->ip.src_addr, 4);

    hdr->ip.checksum = sum.checksum(hdr->ip.checksum);
    if(is_tcp) {
        sum.sub(hdr->L4_header.tcp.src_port);
        hdr->L4_header.tcp.src_port = entry->map.val.wan_port;// 
        sum.add(hdr->L4_header.tcp.src_port);

        hdr->L4_header.tcp.checksum = sum.checksum(hdr->L4_header.tcp.checksum);
    }
    else {
        sum.sub(hdr->L4_header.udp.src_port);
        hdr->L4_header.udp.src_port = entry->map.val.wan_port;
        sum.add(hdr->L4_header.udp.src_port);

        if(hdr->L4_header.udp.checksum != 0)// 0 is same for n & h
            hdr->L4_header.udp.checksum = sum.checksum(hdr->L4_header.udp.checksum);
    }

// try add update
    if(metadata.update) {//
        try_add_update(entry->id_index_host, metadata, timestamp);
    }

// reset "update" & "type"
    net_checksum_calculator metadata_sum;
    metadata_sum.sub(*(checksum_t*)&metadata.version);// "version" is beside "update" & "type"
    metadata.update = 0;
    metadata.type = 2;
    metadata_sum.add(*(checksum_t*)&metadata.version);

    metadata.checksum = metadata_sum.checksum(metadata.checksum);

#ifdef NAT_TEST
    // this does not change checksum
    if(is_tcp) swap(*(checksum_t*)(hdr->L4_header.tcp.payload), *(checksum_t*)(hdr->L4_header.tcp.payload + 2));
    else swap(*(checksum_t*)(hdr->L4_header.udp.payload), *(checksum_t*)(hdr->L4_header.udp.payload + 2));
#endif
// send back
    send_back(hdr, packet_len);
}

void backward_process(host_time_t timestamp, len_t packet_len, hdr_t * const hdr)
{
    nat_metadata_t &metadata = hdr->metadata;

// verify
    bool is_tcp = metadata.map.id.protocol == TCP_PROTOCOL;
    if((is_tcp && packet_len < MIN_TCP_LEN) || (!is_tcp && packet_len < MIN_UDP_LEN))
        return;

    auto val_map_it = val_map.find({metadata.map.id.dst_addr, metadata.map.id.dst_port});
    if(val_map_it == val_map.end()) return;// no such WAN addr & port

    flow_entry_t *entry = val_map_it->second;
    if(entry->type != list_type::inuse) return;

// match
    if(entry->map.id.dst_addr != metadata.map.id.src_addr || 
        entry->map.id.dst_port != metadata.map.id.src_port ||
        entry->map.id.protocol != metadata.map.id.protocol)
        return; // drop on mismatch

    /*
    auto it = map.find(flow_id);
    assert(it != map.end() && it->second == entry);// because it is in use
    */
    
// refresh flow's timestamp
    entry->timestamp_host = timestamp;
    list_move_to_back(&inuse_head, entry);

// heavy hitter detect
    if(entry->id_index_host == entry->val_index_host) {
        // it is not a borrowed entry
        heavy_hitter_count(entry->val_index_host, entry);
    }
    

// translate
    net_checksum_calculator sum;

    sum.sub(&hdr->ip.dst_addr, 4);
    hdr->ip.dst_addr = entry->map.id.src_addr;
    sum.add(&hdr->ip.dst_addr, 4);

    hdr->ip.checksum = sum.checksum(hdr->ip.checksum);
    if(is_tcp) {
        sum.sub(hdr->L4_header.tcp.dst_port);
        hdr->L4_header.tcp.dst_port = entry->map.id.src_port;
        sum.add(hdr->L4_header.tcp.dst_port);

        hdr->L4_header.tcp.checksum = sum.checksum(hdr->L4_header.tcp.checksum);
    }
    else {
        sum.sub(hdr->L4_header.udp.dst_port);
        hdr->L4_header.udp.dst_port = entry->map.id.src_port;
        sum.add(hdr->L4_header.udp.dst_port);

        if(hdr->L4_header.udp.checksum != 0)
            hdr->L4_header.udp.checksum = sum.checksum(hdr->L4_header.udp.dst_port);
    }

// try add update
    if(metadata.update) {//
        try_add_update(entry->id_index_host, metadata, timestamp);
    }

// reset "update" & "type"
    net_checksum_calculator metadata_sum;
    metadata_sum.sub(*(checksum_t*)&metadata.version);// "version" is beside "update" & "type"
    metadata.update = 0;
    metadata.type = 3;
    metadata_sum.add(*(checksum_t*)&metadata.version);

    metadata.checksum = metadata_sum.checksum(metadata.checksum);

#ifdef NAT_TEST
    if(is_tcp) swap(*(checksum_t*)(hdr->L4_header.tcp.payload + 4), *(checksum_t*)(hdr->L4_header.tcp.payload + 6));
    else swap(*(checksum_t*)(hdr->L4_header.udp.payload + 4), *(checksum_t*)(hdr->L4_header.udp.payload + 6));
#endif

// send back
    send_back(hdr, packet_len);
}

void ack_process(host_time_t timestamp, len_t packet_len, hdr_t * hdr)
{
    nat_metadata_t &metadata = hdr->metadata;

    flow_num_t index = metadata.index;

    debug_printf("2\n");
    wait_entry_t *wait_entry = &wait_set[index];
    if(!wait_entry -> is_waiting) return; // Redundant ACK
    debug_printf("3\n");
    // mismatch
    if(/*memcmp(&wait_entry->map.id, &hdr->metadata.id, sizeof(hdr->metadata.id)) != 0 ||
        wait_entry->map.eport != hdr->metadata.switch_port ||*/
        wait_entry->version != metadata.version) 
        return;
    debug_printf("4\n");

    flow_entry_t *entry_sw = wait_entry->old_flow;
    flow_entry_t *entry_nf = wait_entry->new_flow;

    if(entry_sw != NULL) {
        assert(entry_sw->type == list_type::sw);
    }
    assert(entry_nf->type == list_type::inuse);

    //if(entry_sw != NULL) {
    //    entry_sw->is_waiting = 0;// this assignment is useless
    //}

    entry_nf->is_waiting = 0;
    wait_entry->is_waiting = 0;

    list_erase(wait_entry);

    if(metadata.update) {// "update" means accept
        if(entry_sw != NULL) {
            entry_sw->type = list_type::avail;
        }
        entry_nf->type = list_type::sw;

        if(entry_sw != NULL) {
            list_move_to_back(&avail_head[entry_sw->val_index_host], entry_sw);// sw->avail
        }
        list_move_to_back(&sw_head, entry_nf);// inuse->sw

        auto erase_res = id_map.erase(entry_nf->map.id);
        assert(erase_res == 1); 
    }

    debug_printf("\nreceive ACK (%s)\n", hdr->metadata.is_reject? "reject": "accept");
    debug_printf("old map:\n");
    print_map((flow_id_t){0,0,0,0,0,0}, wait_set[index].old_flow->map.val, index);
    debug_printf("new map:\n");
    print_map(wait_set[index].new_flow->map.id, wait_set[index].new_flow->map.val, index);
    debug_printf("version %u -> %u\n", wait_entry->version - 1, wait_entry->version);
}

void do_aging(host_time_t timestamp)
{
    for(flow_entry_t *entry = inuse_head.r, *nxt; 
        entry != &inuse_head; entry = nxt) {
        
        nxt = entry->r;// must first calculate address nxt, or SGfault may happen 

        if(timestamp - entry->timestamp_host <= AGING_TIME_US) break;

        if(entry->is_waiting) continue;// wait to swap to switch

        assert(entry->type == list_type::inuse);

        list_move_to_back(&avail_head[entry->val_index_host], entry);
        entry->type = list_type::avail;
        auto erase_res = id_map.erase(entry->map.id);
        assert(erase_res == 1); 
    }
    // for debug
    static host_time_t last_timestamp = 0;
    if(timestamp - last_timestamp < 200000) return;
    last_timestamp = timestamp;    


    debug_printf("\n");
    flow_entry_t *entry = list_front(&inuse_head);
    int cnt = 0;
    while(entry != &inuse_head) {
        print_map(entry->map.id, entry->map.val, entry->id_index_host);
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

void update_wait_set(host_time_t timestamp)
{
    while(!list_empty(&wait_set_head))
    {
        wait_entry_t *entry = list_front(&wait_set_head);
        if(timestamp - entry->last_req_time_host <= WAIT_TIME_US) break;

        // this is no longer needed, but we still use it to prevent the worst case
        // this is no longer needed, but we still use it to prevent the worst case
        // this is no longer needed, but we still use it to prevent the worst case
        if(timestamp - entry->first_req_time_host > AGING_TIME_US) report_wait_time_too_long();

        entry->last_req_time_host = timestamp;

        send_update(entry->new_flow->id_index_host, 0);// == (entry - &wait_set_head)
        list_move_to_back(&wait_set_head, entry);
    }
}

void nat_process(host_time_t timestamp, len_t packet_len, hdr_t * hdr)
{
    do_aging(timestamp);

    if(packet_len < PACKET_WITH_META_LEN) 
        return;
        
    if(hdr->ethernet.ether_type != htons(TYPE_METADATA)) 
        return;
    
    // only check checksum of header update
    net_checksum_calculator sum;
    sum.add(&hdr->metadata, sizeof(hdr->metadata));
    if(!sum.correct()) return;

    if(hdr->metadata.type == 6)
        ack_process(timestamp, packet_len, hdr);
    else if(hdr->metadata.type == 4) 
        forward_process(timestamp, packet_len, hdr);
    else if(hdr->metadata.type == 5) 
        backward_process(timestamp, packet_len, (hdr_t *) hdr);
}

host_time_t get_mytime()
{
    timespec tm;
    clock_gettime(CLOCK_MONOTONIC, &tm); // don't use pcap's clock
    return (host_time_t)(tm.tv_sec*1000000ull+tm.tv_nsec/1000);
}

void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    //h->ts.tv_sec/tv_usec
    //h->caplen
    //h->len
    if(h->caplen != h->len) return;
    memcpy(buf, bytes, h->len);

    nat_process(get_mytime(), h->len, (hdr_t*)buf);
}

int main(int argc, char **argv)
{
    assert((long long)buf % 64 == 0);
    if(argc != 2) {
        printf("Usage: nf ifname\n");
        return 0;
    }
    char *dev_name = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE]; 
    device = pcap_open_live(dev_name, MAX_FRAME_SIZE, 1, 1, errbuf);
    
    if(device == NULL) {
        printf("cannot open device\n");
        puts(errbuf);
        return 0;
    }

    signal(SIGINT, stop);

    nf_init();

    pcap_setnonblock(device, 1, errbuf);
    
    while(1) {
        pcap_dispatch(device, 4, pcap_handle, NULL);// process at most 4 packets

        update_wait_set(get_mytime());
    }
    
    return 0;
}
