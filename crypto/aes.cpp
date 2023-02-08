#include <iostream>
#include <immintrin.h>
#include "aes.hpp"

static __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    return _mm_xor_si128(temp1, temp2);
}

AES128Block::AES128Block(ByteStream const& init_key) {
    if (init_key.size() != 16)
        throw std::runtime_error("wrong key size");

    __m128i temp1, temp2;

    temp1 = _mm_loadu_si128((__m128i*)init_key.data());
    roundKey[0] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[1] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[2] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[3] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[4] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[5] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[6] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[7] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[8] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[9] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    roundKey[10] = temp1;

}

__m128i AES128Block::encrypt(ByteStream const& plain) const {
    if (plain.size() != 16)
        throw std::runtime_error("wrong plain text size");
        
    __m128i state = _mm_loadu_si128((const __m128i*)plain.data());
    state = _mm_xor_si128(state, roundKey[0]);
    for (int i = 1; i < 10; ++i)
        state = _mm_aesenc_si128(state, roundKey[i]);

    return _mm_aesenclast_si128(state, roundKey[10]);
}

// ByteStream AES128Block::decrypt(ByteStream const& cipher) const {
//     if (cipher.size() != 16)
//         throw std::runtime_error("wrong plain text size");
//     ByteStream out(16);
//     __m128i state = _mm_loadu_si128((const __m128i*)cipher.data());
//     state = _mm_xor_si128(state, roundKey[10]);
//     for (int i = 1; i < 10; ++i)
//         state = _mm_aesdec_si128(state, _mm_aesimc_si128(roundKey[10 - i]));

//     _mm_storeu_si128((__m128i*)out.data(), _mm_aesdeclast_si128(state, roundKey[0]));
    
//     return out;
// }



