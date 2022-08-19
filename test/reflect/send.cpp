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

using std::unordered_map;
using std::queue;
using std::make_pair;
using std::swap;

typedef unsigned short port_t;
typedef unsigned int ip_addr_t;
typedef unsigned int mytime_t;
typedef unsigned short len_t;
typedef unsigned short checksum_t;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

/*
 * Without additional specification, all value in these structs are in network byte order
 */
const u16 TYPE_REFLECT = 0x88b5;

struct ethernet_t{
    u8 dst_addr[6];
    u8 src_addr[6];
    u16 ether_type;
}__attribute__ ((__packed__));

struct reflect_t{
    u8 enable_reflect;
}__attribute__ ((__packed__));

struct hdr_t {
    ethernet_t ethernet;
    reflect_t reflect;
};

u8 buf[1514];

pcap_t *device;

void send_refelect(u8 enable_reflect)
{
    hdr_t * hdr = (hdr_t*)buf;
    hdr->ethernet = {{0, 0, 0, 0, 0, 2}, {0, 0, 0, 0, 0, 1}, htons(TYPE_REFLECT)};
    hdr->reflect = {enable_reflect};
    pcap_sendpacket(device, (u_char *)hdr, sizeof(*hdr));
}

int main(int argc, char **argv)
{
    if(argc != 2) {
        printf("Usage: nfv ifname\n");
        return 0;
    }
    char *dev_name = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE]; 
    device = pcap_open_live(dev_name, 1514, 1, 1, errbuf);
    
    if(device == NULL) {
        printf("cannot open device\n");
        puts(errbuf);
        return 0;
    }
    send_refelect(1);
    sleep(1);
    send_refelect(0);
    /*
    pcap_setnonblock(device, 1, errbuf);
    while(1) {
        pcap_dispatch(device, 4, pcap_handle, NULL);// process at most 4 packets

        timespec tm;
        clock_gettime(CLOCK_MONOTONIC, &tm);

        update_wait_set(tm.tv_sec * 1000000ull + tm.tv_nsec / 1000);
    }
    */
    return 0;
}
