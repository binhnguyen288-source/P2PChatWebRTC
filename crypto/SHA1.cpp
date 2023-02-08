#include "SHA1.hpp"
#include <cstring>
#include <algorithm>
static inline uint32_t rotl(uint32_t value, uint32_t amount) {
    return (value << amount) | (value >> (32u - amount));
}

std::vector<uint8_t> Hash::SHA1(std::string const& value) {
    return Hash::SHA1(std::vector<uint8_t>(value.begin(), value.end()));
}
std::vector<uint8_t> Hash::SHA1(std::vector<uint8_t> value) {

    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;   
    {
        uint64_t ml = value.size() * 8;
        value.push_back(0x80);
        while ((value.size() + 8) % 64 != 0) value.push_back(0x00);
        value.push_back(ml >> 56 & 0xFF);
        value.push_back(ml >> 48 & 0xFF);
        value.push_back(ml >> 40 & 0xFF);
        value.push_back(ml >> 32 & 0xFF);
        value.push_back(ml >> 24 & 0xFF);
        value.push_back(ml >> 16 & 0xFF);
        value.push_back(ml >> 8  & 0xFF);
        value.push_back(ml >> 0  & 0xFF);
    }
    std::array<uint32_t, 80> w;
    for (size_t base = 0; base < value.size(); base += 64) {
        
        for (int i = 0; i < 16; ++i) {
            uint32_t get;
            std::memcpy(&get, &value[base + 4 * i], sizeof(get));
            w[i] = __builtin_bswap32(get);
        }
        for (int i = 16; i < 32; ++i) {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        for (int i = 32; i < 80; ++i) {
            w[i] = rotl(w[i - 6] ^ w[i - 16] ^ w[i - 28] ^ w[i - 32], 2);
        }


        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        for (int i = 0; i < 20; ++i) {
            uint32_t f = (b & c) | (~b & d);
            uint32_t k = 0x5A827999;
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }
        for (int i = 20; i < 40; ++i) {
            uint32_t f = b ^ c ^ d;
            uint32_t k = 0x6ED9EBA1;
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }
        for (int i = 40; i < 60; ++i) {
            uint32_t f = (b & c) | (b & d) | (c & d);
            uint32_t k = 0x8F1BBCDC;
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }
        for (int i = 60; i < 80; ++i) {
            uint32_t f = b ^ c ^ d;
            uint32_t k = 0xCA62C1D6;
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
    }

    std::array<uint32_t, 5> result{h4, h3, h2, h1, h0};
    std::array<uint8_t, 20> bytes;
    std::memcpy(bytes.data(), result.data(), bytes.size());

    return std::vector<uint8_t>(bytes.rbegin(), bytes.rend());
}