#pragma once
#include <immintrin.h>
#include <vector>
#include <cstdint>
#include "../util/ByteStream.hpp"


struct AES128Block {
    __m128i roundKey[11];
    AES128Block(ByteStream const& init_key);
    __m128i encrypt(ByteStream const& plain) const;
    // ByteStream decrypt(ByteStream const& cipher) const;
};