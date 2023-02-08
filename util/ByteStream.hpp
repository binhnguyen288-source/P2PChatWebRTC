#pragma once
#include <string>
#include <vector>
#include <random>
#include <cstring>

using ByteStream = std::vector<uint8_t>;


inline ByteStream operator""_bs(const char* value, size_t length) {
    ByteStream result(length);
    std::memcpy(result.data(), value, length);
    return result;
}

inline ByteStream operator|(ByteStream a, ByteStream const& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

inline ByteStream randomByteStream(uint32_t size) {
    std::mt19937 rng((std::random_device())());
    std::uniform_int_distribution<uint8_t> dist;
    ByteStream result(size);
    for (auto& v : result) v = dist(rng);
    return result;
}


inline void printHex(ByteStream const& v) {
    for (auto x : v) {
        printf("%02x ", x);
    }
    puts("");
}


inline ByteStream ByteStreamFromString(std::string const& v) {
    return ByteStream(v.begin(), v.end());
}


template<uint64_t length>
inline ByteStream ByteStreamFromUintLE(uint64_t v) {
    static_assert(length > 0 && length <= 64 && length % 8 == 0);
    ByteStream result;
    result.reserve(length);
    for (uint64_t i = 0; i < length; i += 8) {
        result.push_back(v >> i);
    }
    return result;
}


template<uint64_t length>
inline ByteStream ByteStreamFromUintBE(uint64_t v) {
    static_assert(length > 0 && length <= 64 && length % 8 == 0);
    ByteStream result;
    result.reserve(length);
    for (uint64_t i = 0; i < length; i += 8) {
        result.push_back(v >> (length - i - 8));
    }
    return result;
}