#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
struct ByteArray {
    uint8_t value[4096];
    uint16_t length;
    constexpr ByteArray operator+(ByteArray const& other) const {
        ByteArray result{};
        for (int i = 0; i < length; ++i)
            result.value[result.length++] = value[i];
        for (int i = 0; i < other.length; ++i)
            result.value[result.length++] = other.value[i];
        return result;
    }
    std::vector<uint8_t> operator()() const {
        std::vector<uint8_t> convert(value, value + length);
        return convert;
    }
};

constexpr uint8_t hex2byte(const char* h) {
    int first  = h[0] > '9' ? 10 + h[0] - 'a' : h[0] - '0';
    int second = h[1] > '9' ? 10 + h[1] - 'a' : h[1] - '0';
    return first << 4 | second;
}

constexpr auto operator "" _hex(const char* str, size_t length) {

    char temp[4096]{};
    size_t length_temp = 0;
    for (size_t i = 0; i < length; ++i) {
        char c = str[i];
        if (c == ' ') continue;
        if (c >= 'A' && c <= 'F') c += 32;
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f'))
            throw "Invalid character";
        temp[length_temp++] = c;
    }
    if (length_temp % 2 != 0) throw "Invalid length";

    
    ByteArray result{};
    int counter = 0;
    for (size_t i = 0; i < length_temp; i += 2) {
        result.value[counter++] = hex2byte(&temp[i]);
    }
    result.length = counter;
    
    return result;
}