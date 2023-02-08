#pragma once

#include <cstdint>
#include "../util/ByteStream.hpp"

ByteStream HKDF_Expand(ByteStream const& key, ByteStream const& info, uint8_t length);
ByteStream HKDF_Expand_Label(ByteStream const& Secret, std::string const& Label, ByteStream const& Context, uint8_t Length);
ByteStream HKDF_Extract(ByteStream const& salt, ByteStream const& material);