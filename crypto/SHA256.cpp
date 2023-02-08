#include "SHA256.hpp"
#include <cstring>
#include <algorithm>
static inline uint32_t rotr(uint32_t value, uint32_t amount) {
    return (value >> amount) | (value << (32u - amount));
}

std::vector<uint8_t> Hash::SHA256(std::vector<uint8_t> message) {

    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;


    static constexpr uint32_t k[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint64_t L = __builtin_bswap64(8 * message.size());
    message.push_back(0x80);
    while ((message.size() + 8) % 64 != 0) message.push_back(0);
    message.insert(message.end(), (uint8_t*)&L, (uint8_t*)&L + sizeof(L));
    uint32_t w[64];

    for (uint32_t chunk = 0; chunk < message.size(); chunk += 64) {
        
        std::memcpy(w, &message[chunk], 64);
        for (int i = 0; i < 16; ++i) {
            w[i] = __builtin_bswap32(w[i]);
        }

        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2] , 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
        h5 = h5 + f;
        h6 = h6 + g;
        h7 = h7 + h;
    }
    std::vector<uint32_t> values{
        h0, h1, h2, h3, h4, h5, h6, h7
    };
    for (auto& x : values) {
        x = __builtin_bswap32(x);
    }
    std::vector<uint8_t> bytes(32);
    std::memcpy(bytes.data(), values.data(), bytes.size());
    return bytes;
}


std::vector<uint8_t> Hash::HMAC_SHA256(std::vector<uint8_t> key, std::vector<uint8_t> const& message) {
    constexpr int blockSize = 64; 
    // resize key to be blockSize

    if (key.size() > blockSize)
        key = SHA256(key);
    
    while (key.size() < blockSize)
        key.push_back(0);
    
    std::vector<uint8_t> o_key_pad = key;
    std::vector<uint8_t> i_key_pad = key;

    for (int i = 0; i < blockSize; ++i) {
        o_key_pad[i] ^= 0x5c;
        i_key_pad[i] ^= 0x36;
    }

    i_key_pad.insert(i_key_pad.end(), message.begin(), message.end());

    auto hash1 = SHA256(i_key_pad);
    o_key_pad.insert(o_key_pad.end(), hash1.begin(), hash1.end());

    return SHA256(o_key_pad);
}

std::vector<uint8_t> Hash::HMAC_SHA256(std::string const& key, std::string const& message) {
    return Hash::HMAC_SHA256(std::vector<uint8_t>(key.begin(), key.end()), std::vector<uint8_t>(message.begin(), message.end()));
}