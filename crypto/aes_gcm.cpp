#include "aes_gcm.hpp"



static inline void gfmul(__m128i a, __m128i b, __m128i *res) {
    __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
    // tmp6 = high 128 bit result
    // tmp3 = lo 128 bit result
    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);
    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);
    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);
    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);
    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);
    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);
    tmp6 = _mm_xor_si128(tmp6, tmp3);
    *res = tmp6;
}



ByteStream AES128_GCM::encrypt(ByteStream stream, ByteStream aad) {
    uint32_t ctr = 1;
    const uint64_t bytesC = stream.size();
    const uint64_t lenA = 8 * aad.size();

    static const __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    // padding
    while (stream.size() % 16 != 0) stream.push_back(0);
    while (aad.size() < 16) aad.push_back(0x00);

    ByteStream iv_seq = iv;
    for (int i = 0; i < 8; ++i) {
        iv_seq[iv_seq.size() - 1 - i] ^= (seq >> (8 * i)) & 0xff;
    }
    
    const __m128i H = _mm_shuffle_epi8(cipherBlock.encrypt(ByteStream(16, 0)), BSWAP_MASK);
    __m128i T = cipherBlock.encrypt(iv_seq | ByteStreamFromUintBE<32>(ctr++)); // to be xor'ed at the end
    __m128i X = _mm_shuffle_epi8(_mm_loadu_si128((__m128i*)aad.data()), BSWAP_MASK);
    gfmul(X, H, &X);

    for (uint32_t i = 0; i < stream.size(); i += 16) {
        __m128i ivCtrCipher = cipherBlock.encrypt(iv_seq | ByteStreamFromUintBE<32>(ctr++));
        __m128i cipher = _mm_loadu_si128((__m128i*)&stream[i]);
        cipher = _mm_xor_si128(cipher, ivCtrCipher);
        _mm_storeu_si128((__m128i*)&stream[i], cipher);
        if (bytesC % 16 != 0 && i + 16 > bytesC) {
            for (int i = bytesC % 16; i < 16; ++i) {
                ((uint8_t*)&cipher)[i] = 0;
            }
        }
        X = _mm_xor_si128(X, _mm_shuffle_epi8(cipher, BSWAP_MASK));
        gfmul(X, H, &X);
    }
    __m128i lenAlenC = { bytesC * 8, lenA };
    X = _mm_xor_si128(X, lenAlenC);
    gfmul(X, H, &X);
    X = _mm_shuffle_epi8(X, BSWAP_MASK);
    T = _mm_xor_si128(T, X);

    stream.resize(bytesC);
    stream.insert(stream.end(), (uint8_t*)&T, (uint8_t*)&T + 16);
    ++seq;
    return stream;
}

ByteStream AES128_GCM::decrypt(ByteStream stream, ByteStream aad) {
    __m128i T = _mm_loadu_si128((__m128i*)&stream[stream.size() - 16]);
    stream.resize(stream.size() - 16);

    uint32_t ctr = 1;
    const uint64_t bytesC = stream.size();
    const uint64_t lenA = 8 * aad.size();

    static const __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    // padding
    while (stream.size() % 16 != 0) stream.push_back(0);
    while (aad.size() < 16) aad.push_back(0x00);

    ByteStream iv_seq = iv;
    for (int i = 0; i < 8; ++i) {
        iv_seq[iv_seq.size() - 1 - i] ^= (seq >> (8 * i)) & 0xff;
    }
    
    const __m128i H = _mm_shuffle_epi8(cipherBlock.encrypt(ByteStream(16, 0)), BSWAP_MASK);
    T = _mm_xor_si128(T, cipherBlock.encrypt(iv_seq | ByteStreamFromUintBE<32>(ctr++))); // to be xor'ed at the end
    __m128i X = _mm_shuffle_epi8(_mm_loadu_si128((__m128i*)aad.data()), BSWAP_MASK);
    gfmul(X, H, &X);

    for (uint32_t i = 0; i < stream.size(); i += 16) {
        __m128i ivCtrCipher = cipherBlock.encrypt(iv_seq | ByteStreamFromUintBE<32>(ctr++));
        __m128i cipher = _mm_loadu_si128((__m128i*)&stream[i]);
        _mm_storeu_si128((__m128i*)&stream[i], _mm_xor_si128(cipher, ivCtrCipher));
        X = _mm_xor_si128(X, _mm_shuffle_epi8(cipher, BSWAP_MASK));
        gfmul(X, H, &X);
    }
    __m128i lenAlenC = { bytesC * 8, lenA };
    X = _mm_xor_si128(X, lenAlenC);
    gfmul(X, H, &X);
    X = _mm_shuffle_epi8(X, BSWAP_MASK);
    T = _mm_xor_si128(T, X);
    if (!_mm_testz_si128(T, T))
        throw std::runtime_error("invalid stream");
    stream.resize(bytesC);
    ++seq;
    return stream;

}