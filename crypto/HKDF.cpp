
#include "HKDF.hpp"
#include "SHA256.hpp"


ByteStream HKDF_Expand(ByteStream const& key, ByteStream const& info, uint8_t length) {
    auto result = Hash::HMAC_SHA256(key, info | ByteStream{0x01});
    result.resize(length);
    return result;
}

ByteStream HKDF_Expand_Label(ByteStream const& Secret, std::string const& Label, ByteStream const& Context, uint8_t Length) {
    ByteStream HKDFLabel = ByteStream{0, Length} | 
                           ByteStreamFromUintBE<8>(Label.length() + 6) | ByteStreamFromString("tls13 " + Label) |
                           ByteStreamFromUintBE<8>(Context.size()) | Context;

    return HKDF_Expand(Secret, HKDFLabel, Length);
}

ByteStream HKDF_Extract(ByteStream const& salt, ByteStream const& material) {
    return Hash::HMAC_SHA256(salt, material);
}