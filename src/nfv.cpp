#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <time.h>
#include <unordered_map>
#include <signal.h>
#include <assert.h>
#include <unistd.h>

typedef unsigned short port_t;
typedef unsigned int ip_addr_t;
typedef unsigned long long mytime_t;
typedef unsigned short len_t;
typedef unsigned short checksum_t;

struct ethernet_t{
    u_char dst_addr[6];
    u_char src_addr[6];
    unsigned short ether_type;
}__attribute__ ((__packed__));

struct flow_id_t{
    ip_addr_t   src_addr;
    ip_addr_t   dst_addr;
    port_t      src_port;
    port_t      dst_port;
    u_char      protocol;
    u_char      zero;
}__attribute__ ((__packed__));

struct map_entry_t{
    flow_id_t id;
    port_t eport;
}__attribute__ ((__packed__));

enum message_t: unsigned short{
    null = 0,
    timeout = 1,
    require_update = 2,
    accept_update = 3,
    reject_update = 4
};

struct update_t{
    map_entry_t map; 
    message_t type;
    checksum_t checksum;
}__attribute__ ((__packed__));

struct ip_t{
    u_char unused[9];
    u_char protocol;
    checksum_t checksum;
    ip_addr_t src_addr;
    ip_addr_t dst_addr;
}__attribute__ ((__packed__));

struct tcp_t{
    port_t src_port;
    port_t dst_port;
    u_char unused1[12];
    checksum_t checksum;
    u_char unused2[2];
}__attribute__ ((__packed__));

struct udp_t{
    port_t src_port;
    port_t dst_port;
    u_char unused[2];
    checksum_t checksum;
}__attribute__ ((__packed__));

union L4_header_t{
    tcp_t tcp;
    udp_t udp;
};

struct hdr_t{
    ethernet_t ethernet;
    update_t update;
    ip_t ip;
    L4_header_t L4_header;
};

const int max_frame_size = 1514;
pcap_t device;
u_char buf[max_frame_size] __attribute__ ((aligned (64)));
hdr_t * const hdr = (hdr_t *)buf;

void stop(int signo)
{
    _exit(0);
}

void nat_process(mytime_t ts, len_t packet_len)
{

}

void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    //h->ts.tv_sec/tv_usec
    //h->caplen
    //h->len
    if(h->caplen != h->len) return;
    memcpy(buf, bytes, h->len);
    nat_process(h->ts.tv_sec * 1000000ull + h->ts.tv_usec, h->len);
}

int main(int argc, char **argv)
{
    assert((long long)buf % 64 == 0);
    if(argc != 2) {
        printf("Usage: nfv ifname\n");
        return 0;
    }
    char *dev_name = argv[1];
    char errbuf[256];
    device = pcap_open_live(dev_name, max_frame_size, 1, 0, errbuf);
    
    if(device == NULL) {
        printf("cannot open device\n");
        errbuf[sizeof(errbuf)-1] = 0;
        puts(errbuf);
        return 0;
    }

    signal(SIGINT, stop);

    pcap_loop(device, -1, pcap_handle, NULL);
    return 0;
}