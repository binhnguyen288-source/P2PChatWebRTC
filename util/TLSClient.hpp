#pragma once
#include "../util/hexutil.hpp"
#include "../util/ByteStream.hpp"
#include "../crypto/curve25519.hpp"
#include "../crypto/TLSKeyCalc.hpp"
#include "../crypto/aes_gcm.hpp"
#include "../util/TLSUtil.hpp"
struct TLSClient {
    TLSClient(const std::string& serverIp, const std::string& serverPort) : sock(serverIp.c_str(), serverPort.c_str()), app_encryptor{}, app_decryptor{}, ptr{}, size{} {

        ByteStream privateKey = randomByteStream(32);

        ByteStream Extension = ByteStream{0x00, 0x00} | // server name
                                        ByteStreamFromUintBE<16>(serverIp.length() + 5) |
                                        ByteStreamFromUintBE<16>(serverIp.length() + 3) |
                                        ByteStream{0x00} | 
                                        ByteStreamFromUintBE<16>(serverIp.length()) | 
                                        ByteStreamFromString(serverIp) |
                                    ByteStream{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00} | // EC point compression [uncompressed]
                                    ByteStream{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d} | // supported groups [x25519]
                                    ByteStream{0x00, 0x23, 0x00, 0x00} |
                                    ByteStream{0x00, 0x16, 0x00, 0x00} | 
                                    ByteStream{0x00, 0x17, 0x00, 0x00} | 
                                    ByteStream{0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x04} | // signature algorithm [RSA-PSS-RSAE-SHA256]
                                    ByteStream{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04} | // supported version [tls1.3]
                                    ByteStream{0x00, 0x2d, 0x00, 0x02, 0x01, 0x01} |
                                    ByteStream{0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20} | // key share
                                        generatePublicKey(privateKey);
        ByteStream clientHello = ByteStream{0x03, 0x03} | 
                                randomByteStream(32) |
                                ByteStream{0x20} | randomByteStream(32) |
                                ByteStream{0x00, 0x02, 0x13, 0x01} |
                                ByteStream{0x01, 0x00} | 
                                ByteStreamFromUintBE<16>(Extension.size()) | Extension;
        ByteStream headerRecord = ByteStream{0x16, 0x03, 0x01} | ByteStreamFromUintBE<16>(clientHello.size() + 4);
        clientHello = ByteStream{0x01} | ByteStreamFromUintBE<24>(clientHello.size()) | clientHello;
        auto clientHelloRecord = headerRecord | clientHello;

        sock.sendByteStream(clientHelloRecord);

        ByteStream serverHello;
        auto header = sock.readExactly(5);
        serverHello = sock.readExactly(header[3] << 8 | header[4]);

        ByteStream keyShare;
        for (size_t i = 76; i < serverHello.size();) {
            uint16_t extType = serverHello[i] << 8 | serverHello[i + 1];
            uint16_t extLength = serverHello[i + 2] << 8 | serverHello[i + 3];
            if (extType == 0x0033) {
                keyShare = ByteStream(&serverHello[i + 8], &serverHello[i + 40]);
            }
            i = i + 4 + extLength;
        }

        header = sock.readExactly(5);
        sock.readExactly(header[3] << 8 | header[4]);
        
        HandshakeKey handshakeKey(mulKeys(privateKey, keyShare), Hash::SHA256(clientHello | serverHello));

        AES128_GCM decryptor(handshakeKey.server_handshake_iv, handshakeKey.server_handshake_key);
        AES128_GCM encryptor(handshakeKey.client_handshake_iv, handshakeKey.client_handshake_key);
        header = sock.readExactly(5);
        auto serverentofinished = decryptor.decrypt(sock.readExactly(header[3] << 8 | header[4]), header);
        serverentofinished.resize(serverentofinished.size() - 1);
        ByteStream clientCipherChange = ByteStream{
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01  
        };
        ByteStream clientFinished = ByteStream{0x14, 0x00, 0x00, 0x20} | Hash::HMAC_SHA256(
            HKDF_Expand_Label(handshakeKey.client_handshake_traffic_secret, "finished", ByteStream{}, 32), 
            Hash::SHA256(clientHello | serverHello | serverentofinished)
        );


        auto sendFinished = clientCipherChange | makeEncryptedRecord(encryptor.encrypt(clientFinished | ByteStream{0x16}, makeEncryptedHeader(clientFinished)));

        sock.sendByteStream(sendFinished);

        ApplicationKey appKey(handshakeKey.handshake_secret, Hash::SHA256(clientHello | serverHello | serverentofinished));
        app_encryptor = new AES128_GCM(appKey.client_application_iv, appKey.client_application_key);
        app_decryptor = new AES128_GCM(appKey.server_application_iv, appKey.server_application_key);
    }
    void readRecord() {
        for (;;) {
            auto header = sock.readExactly(5);
            uint32_t recordSize = header[3] << 8 | header[4];
            assertThrow(recordSize <= (1u << 14) + 17, "record size too big");
            auto response = app_decryptor->decrypt(sock.readExactly(recordSize), header);
            if (response.back() == 0x16)
                continue;  // server sent ticket, but we just ignore
            if (response.back() != 0x17)
                throw std::runtime_error("payload trailing error");
            ptr = 0;
            size = response.size() - 1;
            std::memcpy(readBuffer, response.data(), size);
            break;
        }
    }
    uint8_t getByte() {
        if (ptr == size) readRecord();
        return readBuffer[ptr++];
    }
    void write(void* data, size_t length) {
        uint8_t* ptr = static_cast<uint8_t*>(data);
        while (length > 0) {
            uint32_t sendLength = std::min(length, 1llu << 14);
            ByteStream message(ptr, ptr + sendLength);
            auto encrypted = app_encryptor->encrypt(message | ByteStream{0x17}, makeEncryptedHeader(message));
            sock.sendByteStream(makeEncryptedRecord(encrypted));
            length -= sendLength;
            ptr += sendLength;
        }
    }
    ~TLSClient() {
        delete app_encryptor;
        delete app_decryptor;
    }
private:
    BufferedSocket sock;
    AES128_GCM* app_encryptor;
    AES128_GCM* app_decryptor;
    //ByteStream readBuffer;
    uint8_t readBuffer[16384];
    int ptr, size;
};