#include "TLS_TCPServer.hpp"

TLS_TCPServer::TLS_TCPServer(uint16_t port) : 
    sock_fd{socket(AF_INET, SOCK_STREAM, 0)}
{
    if (sock_fd < 0)
        throw std::runtime_error("Can't create socket");

    int set = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&set, sizeof(set));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock_fd, (sockaddr*)&addr, sizeof(sockaddr_in)) < 0)
        throw std::runtime_error("Can't bind socket"); 

    if (listen(sock_fd, 32) < 0)
        throw std::runtime_error("Can't listen on socket");
}

TLSClientHandle* TLS_TCPServer::accept() {
    SOCKET fd_client = INVALID_SOCKET;
    for (;;) {
        try {
            fd_client = ::accept(sock_fd, NULL, NULL);
            if (fd_client < 0)
                throw std::runtime_error("accept failed");
            
            return new TLSClientHandle(fd_client);
        } catch (std::exception const& e) {
            std::cout << e.what() << std::endl;
            if (fd_client != INVALID_SOCKET) closesocket(fd_client);
            fd_client = INVALID_SOCKET;
        }
    }
}