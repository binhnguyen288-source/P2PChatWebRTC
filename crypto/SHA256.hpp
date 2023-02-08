#pragma once
#include <cstdint>
#include <vector>
#include <string>
namespace Hash {
    std::vector<uint8_t> SHA256(std::vector<uint8_t> message);
    std::vector<uint8_t> HMAC_SHA256(std::vector<uint8_t> key, std::vector<uint8_t> const& message);
    std::vector<uint8_t> HMAC_SHA256(std::string const& key, std::string const& message);
}