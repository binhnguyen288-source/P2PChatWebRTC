#pragma once
#include "ByteStream.hpp"
#include "hexutil.hpp"
#include "socket.hpp"
#include <stdexcept>





inline ByteStream makeEncryptedHeader(ByteStream payload) {
    return ByteStream{0x17, 0x03, 0x03} | ByteStreamFromUintBE<16>(payload.size() + 17);
}

inline ByteStream makeEncryptedRecord(ByteStream encrypted) {
    return ByteStream{0x17, 0x03, 0x03} | ByteStreamFromUintBE<16>(encrypted.size()) | encrypted;
}



