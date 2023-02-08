#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <cstring>

std::vector<uint8_t> generatePublicKey(std::vector<uint8_t> privateKey);
std::vector<uint8_t> mulKeys(std::vector<uint8_t> privateKey, std::vector<uint8_t> const& otherPublic);