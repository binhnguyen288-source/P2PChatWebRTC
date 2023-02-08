#pragma once

#include <stdexcept>
#include <cstdint>
#include <algorithm>
#include <chrono>
#include <iostream>
#include "util/socket.hpp"
#include "util/TLSServer.hpp"
using std::uint16_t;
using namespace std::chrono;

struct TLS_TCPServer {
    TLS_TCPServer(uint16_t port);
    TLSClientHandle* accept();
    ~TLS_TCPServer() { closesocket(sock_fd); }
private:
    SOCKET sock_fd;
};
