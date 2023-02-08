#pragma once
#include "aes.hpp"
#include <stdexcept>

struct AES128_GCM {
    const ByteStream iv; // must be 96 bits or 12 bytes
    const AES128Block cipherBlock;
    uint64_t seq;
    AES128_GCM(ByteStream const& iv, ByteStream const& key) : 
        iv(iv), cipherBlock(key), seq{} {}
    
    ByteStream encrypt(ByteStream stream, ByteStream aad);
    ByteStream decrypt(ByteStream stream, ByteStream aad);
};