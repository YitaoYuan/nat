#include "type.h"

/*
 *  input: bit stream, do not reverse bit 
 *  output: CRC value, in host's byte order
 */

template<typename T, u32 crc_poly>
class my_hash{
    u32 crc_value[256];
    u32 crc32_bit(u8 data) const
    {
        u32 crc_bit_value[2] = {0, crc_poly};
        u32 res = 0;
        for(int i = 7; i >= 0; i--) 
            res = res << 1 ^ crc_bit_value[res >> 31 ^ (data >> i & 1)];
        return res;
    }
    void crc_initialize() 
    {
        for(u32 i = 0; i < 256; i++) 
            crc_value[i] = crc32_bit(i);
    }
    u32 crc32(u8 *data, int len) const
    {
        u32 res = 0;//crc_init;
        for(int i = 0; i < len; i++) 
            res = res << 8 ^ crc_value[res >> 24 ^ data[i]];
        return res;// ^ crc_xor;
    }
public:
    my_hash () {
        crc_initialize();
    }
    size_t operator ()(const T &key) const{
        return crc32((u8*) &key, sizeof(T));
    }
};

template<typename T>
struct mem_equal{
    bool operator ()(const T &lhs, const T &rhs) const{
        return memcmp(&lhs, &rhs, sizeof(T)) == 0;
    }
};