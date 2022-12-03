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
protected:
    host_checksum_calculator() {
        value = 0;
    }
    // Don't use the functions below directly in your code, it's dangerous
    void add(checksum_t x) {
        value = add(value, x);
    }
    void sub(checksum_t x) {
        add(~x);
    }
    checksum_t checksum(checksum_t old_checksum) {
        return zero_filter(add(old_checksum, ~value));
    }
public:
    bool correct() {
        return (checksum_t)~value == 0;
    }
};

/*
 * Why I didn't designed an member function like "void add(checksum_t)"
 * for "class net_checksum_calculator" ?
 * Because it is dangerous, you can easily break "strict-aliasing" rule 
 * through this kind of API and cause a BUG.
 * And that's also the reason I use "memcpy" in the below functions.
 */
#define CHECKSUM_SIZE sizeof(checksum_t)

class net_checksum_calculator: public host_checksum_calculator{
private:
    checksum_t read_checksum(void* data) {
        checksum_t ret;
        // You must use memcpy to follow "strict-aliasing".
        // "Memcpy" uses "char*" which will not break the rule.
        memcpy(&ret, data, CHECKSUM_SIZE);
        return ret;
    }
public:
    void add(void *net_data, size_t len_in_byte = CHECKSUM_SIZE) {
        assert(len_in_byte % CHECKSUM_SIZE == 0);
        char *data = (char*)net_data;
        for(size_t i = 0; i < len_in_byte; i += CHECKSUM_SIZE) 
            host_checksum_calculator::add(ntohs(read_checksum(data + i)));
    }
    void sub(void *net_data, size_t len_in_byte = CHECKSUM_SIZE) {
        assert(len_in_byte % CHECKSUM_SIZE == 0);
        char *data = (char*)net_data;
        for(size_t i = 0; i < len_in_byte; i += CHECKSUM_SIZE) 
            host_checksum_calculator::sub(ntohs(read_checksum(data + i)));
    }
    checksum_t checksum(void *old_checksum = NULL) {
        if(old_checksum == NULL) return htons(host_checksum_calculator::checksum(0));
        return htons(host_checksum_calculator::checksum(ntohs(read_checksum(old_checksum))));
    }
};