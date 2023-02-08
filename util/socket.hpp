#pragma once
#include <stdexcept>
#include "../util/ByteStream.hpp"
#if _WIN32 == 1
    #include <ws2tcpip.h>
#else
    #include <netdb.h>
    #include <unistd.h>
    using SOCKET = int;
    #define closesocket close
#endif
inline void InitSocketLib() {
#if _WIN32 == 1
    WSAData data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        throw std::runtime_error("winsock2 init failed");
#endif
}

inline void CleanupSocketLib() {
#if _WIN32
    WSACleanup();
#endif
}

inline void assertThrow(bool expression, std::string const& fail_msg) {
    if (!expression)
        throw std::runtime_error(fail_msg);
}


struct BufferedSocket {
    BufferedSocket(SOCKET fd) : sock(fd), ptr{}, size{} { assertThrow(fd != INVALID_SOCKET, "Invalid socket"); }
    BufferedSocket(const char* serverIp, const char* port) : BufferedSocket(socket(AF_INET, SOCK_STREAM, 0)) {
        addrinfo* ai;
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        getaddrinfo(serverIp, port, &hints, &ai);
        int ret = connect(sock, ai->ai_addr, ai->ai_addrlen);
        freeaddrinfo(ai);
        if (ret < 0) {
            if (sock != INVALID_SOCKET)
                closesocket(sock);
            throw std::runtime_error("can't connect to server");
        }
    }
    template<bool peek = false>
    uint8_t getByte() {
        if (ptr == size) {
            ptr = 0;
            size = recv(sock, buffer, sizeof(buffer), 0);
            if (size <= 0)
                throw std::runtime_error("recv failed");
        }
        if constexpr (peek == false) return buffer[ptr++];
        else return buffer[ptr];
    }
    ByteStream readExactly(uint64_t n) {
        if (n == 0) return {};
        ByteStream result;
        result.reserve(n);
        do {
            if (ptr == size) {
                ptr = 0;
                size = recv(sock, buffer, sizeof(buffer), 0);
                if (size <= 0)
                    throw std::runtime_error("recv failed");
            }
            uint64_t readSize = std::min(n - result.size(), (uint64_t)(size - ptr));
            result.insert(result.end(), &buffer[ptr], &buffer[ptr] + readSize);
            ptr += readSize;
        } while (result.size() < n);

        return result;
    }
    void sendByteStream(ByteStream const& bytes) {
        uint32_t ptr = 0;
        while (ptr < bytes.size()) {
            int nSent = send(sock, (char*)&bytes[ptr], bytes.size() - ptr, 0);
            assertThrow(nSent > 0, "sent failed");
            ptr += nSent;
        }
    }
    template<uint64_t length>
    uint64_t getUintLE() {
        static_assert(length > 0 && length <= 64 && length % 8 == 0);
        uint64_t result = 0;
        for (uint64_t i = 0; i < length; i += 8) {
            result |= getByte() << i;
        }
        return result;
    }
    template<uint64_t length>
    uint64_t getUintBE() {
        static_assert(length > 0 && length <= 64 && length % 8 == 0);
        uint64_t result = 0;
        for (uint64_t i = 0; i < length; i += 8) {
            result = result << 8 | getByte();
        }
        return result;
    }
    ~BufferedSocket() {
        if (sock != INVALID_SOCKET) closesocket(sock);
    }
private:
    SOCKET sock;
    int ptr, size;
    char buffer[16384 + 17];
};