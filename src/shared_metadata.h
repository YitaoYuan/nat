#define SHARED_LAN_ADDR 0xC0A80100
#define SHARED_LAN_ADDR_MASK 0xFFFFFF00
#define SHARED_NAT_ADDR 0xC0A802FE

#define SHARED_PORT_MIN 30000
#define SHARED_PORT_MAX 31000
#define SWITCH_PORT_NUM_LOG 8
#define SHARED_SWITCH_PORT_NUM (1<<SWITCH_PORT_NUM_LOG)

#define SHARED_AGING_TIME_US 10000000

#define SHARED_TYPE_METADATA 0x88B5

#define SHARED_SWITCH_INNER_MAC 0x1
#define SHARED_NF_INNER_MAC 0x2

//#define DEBUG 1