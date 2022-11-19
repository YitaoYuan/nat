#include <arpa/inet.h>
#include "type.h"

class host_checksum_calculator{
    // TODO 
private:
    checksum_t value;
    checksum_t add(checksum_t x, checksum_t y) {
        u32 sum = (u32)x + (u32)y;
        return (sum & 0xffff) + (sum >> 16);
    }
    checksum_t zero_filter(checksum_t x) {
        return x ? x : ~x;
    } 
public:
    host_checksum_calculator() {
        value = 0;
    }
    void add(checksum_t x) {
        value = add(value, x);
    }
    void sub(checksum_t x) {
        add(~x);
    }
    bool correct() {
        return (checksum_t)~value == 0;
    }
    checksum_t checksum(checksum_t old_checksum = 0) {
        return zero_filter(add(old_checksum, ~value));
    }
};

class net_checksum_calculator: public host_checksum_calculator{
public:
    void add(checksum_t x) {
        host_checksum_calculator::add(ntohs(x));
    }
    void sub(checksum_t x) {
        host_checksum_calculator::sub(ntohs(x));
    } 
    checksum_t checksum(checksum_t old_checksum = 0) {
        return htons(host_checksum_calculator::checksum(ntohs(old_checksum)));
    }
    void add(void *net_data, size_t len_in_byte) {
        assert(len_in_byte % 2 == 0);
        for(checksum_t *i = (checksum_t *)net_data; i < (checksum_t *)(len_in_byte + (u8*)net_data); i++) 
            add(*i);
    }
    void sub(void *net_data, size_t len_in_byte) {
        assert(len_in_byte % 2 == 0);
        for(checksum_t *i = (checksum_t *)net_data; i < (checksum_t *)(len_in_byte + (u8*)net_data); i++) 
            sub(*i);
    }
};