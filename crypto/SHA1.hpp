
#pragma once
#include <cstdint>
#include <vector>
#include <array>
#include <string>
namespace Hash {
    std::vector<uint8_t> SHA1(std::vector<uint8_t> value);
    std::vector<uint8_t> SHA1(std::string const& value);

}