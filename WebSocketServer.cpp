#include "TLS_TCPServer.hpp"
#include "crypto/SHA1.hpp"
#include <unistd.h>
#include <thread>
#include <mutex>
#include <iostream>
#include <cstring>
#include <vector>
#include "HTTPUtil.hpp"
#include "json.hpp"
#include "util/base64.hpp"
namespace ThreadLog {
    static std::mutex logMutex;
    template<typename T>
    void print(T const& value) {
        logMutex.lock();
        std::cout << value << std::flush;
        logMutex.unlock();
    }
}
#include "jwt_secret.hpp"
std::string handshake_websocket(TLSClientHandle* client) {

    const auto headers = getHTTPHeader(*client);
    auto splitted = split(split(headers.at("Cookie"), '=')[1], '.');
    auto payload = splitted[0];
    auto signature = Base64URL::encode(Hash::HMAC_SHA256(JWT_SECRET, payload));
    assertThrow(signature == splitted[1], "signature failed");
    std::string userId = nlohmann::json::parse(Base64URL::decode(payload)).at("id").get<std::string>();
    auto sha1_hash = Hash::SHA1(headers.at("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + Base64::encode(sha1_hash.data(), sha1_hash.size()) + "\r\n"
        "\r\n";
    client->write(response.data(), response.length());
    return userId;
}
struct ThreadSafeMap {

    bool insert(std::string const& v, TLSClientHandle* client) {
        std::scoped_lock lck(mtx);
        return map.insert({ v, client }).second;
    }

    void erase(std::string const& at) {
        std::scoped_lock lck(mtx);
        map.erase(at);
    }

    TLSClientHandle* at(std::string const& id) {
        std::scoped_lock lck(mtx);
        auto find = map.find(id);
        return find == map.end() ? nullptr : find->second;
    }
private:
    std::unordered_map<std::string, TLSClientHandle*> map;
    std::mutex mtx;
};

static ThreadSafeMap idToClientHandle;


void handle_client(TLSClientHandle* client) {
    std::string userId;
    try {
            
        userId = handshake_websocket(client);
        if (!idToClientHandle.insert(userId, client)) {
            userId.clear();
            throw std::runtime_error("you should not run 2 instance");
        }

        ThreadLog::print(userId + "\n");

        std::string cur_message;
        for (;;) {
            uint8_t first_byte = client->getByte();
            const uint8_t fin = first_byte & 0x80;
            const uint8_t opcode = first_byte & 0xf;
            if (opcode != 0x1 && opcode != 0x0) 
                throw std::runtime_error("Not supported opcode " + std::to_string(opcode));
            uint8_t second_byte = client->getByte();
            if (!(second_byte & 0x80))
                throw std::runtime_error("Message from client must be masked");
            uint64_t payload_length = (second_byte & 0x7f);
            if (payload_length >= 126) {
                
                int loop = payload_length == 126 ? 1 : 7;
                payload_length = client->getByte();
                while (loop--)
                    payload_length = payload_length << 8 | client->getByte();
            }
            uint8_t mask[4] = {0};
            for (int i = 0; i < 4; ++i)
                mask[i] = client->getByte();
            for (uint64_t i = 0; i < payload_length; ++i) {
                cur_message.push_back(client->getByte() ^ mask[i % 4]);
            }
            if (fin) {
                // message callback here
                
                auto json = nlohmann::json::parse(cur_message);
                cur_message.clear();
                
                nlohmann::json sendJson;

                TLSClientHandle* dst = idToClientHandle.at(json.at("peerId").get<std::string>());
                if (dst == nullptr) {
                    dst = client;
                    sendJson = nlohmann::json{
                        {"peerId", json.at("peerId")},
                        {"message", nlohmann::json{{"rejected", true}}}
                    };
                }
                else {
                    sendJson = nlohmann::json{
                        {"peerId", userId},
                        {"message", json}
                    };
                }
                const std::string dump = sendJson.dump();

                ByteStream sendBackFrame;
                if (dump.length() < 126) {
                    sendBackFrame = ByteStream{0x81} | ByteStreamFromUintBE<8>(dump.length());
                } else if (dump.length() < 65536) {
                    sendBackFrame = ByteStream{0x81, 126} | ByteStreamFromUintBE<16>(dump.length());
                } else {
                    sendBackFrame = ByteStream{0x81, 127} | ByteStreamFromUintBE<64>(dump.length());
                }
                sendBackFrame.insert(sendBackFrame.end(), dump.begin(), dump.end());
                {
                    std::scoped_lock lck(dst->mtx);
                    dst->write(sendBackFrame.data(), sendBackFrame.size());
                }
            }
        }
    }
    catch (std::exception const& e) {
        ThreadLog::print(e.what());
        ThreadLog::print("\n");
    }
    catch (...) {
        ThreadLog::print("Unknown exception");
    }
    if (!userId.empty())
        idToClientHandle.erase(userId);
    ThreadLog::print("Closed connection for " + userId + "\n");
    delete client;
}


int main() {
    InitSocketLib();
    TLS_TCPServer server(2345);

    for (;;) {
        TLSClientHandle* client = server.accept();
        std::thread worker(handle_client, client);
        worker.detach();
    }
    CleanupSocketLib();
    return 0;
}