#pragma once
#include "../util/TLSUtil.hpp"
#include "../crypto/aes_gcm.hpp"
#include "../crypto/RSAPSS.hpp"
#include "../crypto/TLSKeyCalc.hpp"
#include "../crypto/curve25519.hpp"
#include <unordered_map>
#include <chrono>
#include <mutex>
struct TLSClientHandle {
    

   
    
    TLSClientHandle(SOCKET fd) : sock(fd), decryptor{nullptr}, encryptor{nullptr}, ptr{}, size{} {
        
        assertThrow(sock.getByte() == 0x16, "client hello record header is not handshake");
        sock.getUintBE<16>();
        uint16_t clientHelloRecordSize = sock.getUintBE<16>();
        const ByteStream clientHello = sock.readExactly(clientHelloRecordSize);
        const auto [session_id, otherPublicKey] = parseClientHello(clientHello);

        const ByteStream privateKey = randomByteStream(32);
        const uint64_t handshakeLength = 86 + session_id.size();
        const ByteStream serverHelloRecordSizeHeader = ByteStreamFromUintBE<16>(handshakeLength + 4);
        const ByteStream serverHello =  ByteStream{0x02} |
                                        ByteStreamFromUintBE<24>(handshakeLength) |
                                        ByteStream{0x03, 0x03} | // server version legacy tls 1.2
                                        randomByteStream(32) |   // server random
                                        ByteStreamFromUintBE<8>(session_id.size()) | session_id | 
                                        ByteStream{
                                            0x13, 0x01, // TLS_AES_128_GCM_SHA256
                                            0x00, // null compression
                                            0x00, 0x2e, // extension length
                                            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported version tls 1.3
                                            0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 // key share x25519
                                        } | generatePublicKey(privateKey);
        
      
        sock.sendByteStream(
            ByteStream{0x16, 0x03, 0x03} | serverHelloRecordSizeHeader | serverHello | // server hello
            ByteStream{0x14, 0x03, 0x03, 0x00, 0x01, 0x01} // change cipher spec
        );
        ByteStream shared_secret = mulKeys(privateKey, otherPublicKey);
        HandshakeKey handshakeKey(shared_secret, Hash::SHA256(clientHello | serverHello));
        AES128_GCM handshakeSend(handshakeKey.server_handshake_iv, handshakeKey.server_handshake_key);

        static const ByteStream certBuffer = "30 82 05 25 30 82 04 0d a0 03 02 01 02 02 12 04 0d c9 e7 f8 c3 dd cc d4 e5 8b d1 3e 78 ec 9c 2d 93 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 32 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 16 30 14 06 03 55 04 0a 13 0d 4c 65 74 27 73 20 45 6e 63 72 79 70 74 31 0b 30 09 06 03 55 04 03 13 02 52 33 30 1e 17 0d 32 32 31 31 31 39 30 39 31 38 32 37 5a 17 0d 32 33 30 32 31 37 30 39 31 38 32 36 5a 30 1a 31 18 30 16 06 03 55 04 03 13 0f 76 65 72 62 61 6c 2e 64 64 6e 73 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 c3 1c 34 d3 9b 89 92 17 c8 3d 46 b1 52 77 6f 23 f6 bf 7e 5e b5 a0 e6 e1 c0 d1 1e 55 78 bb 66 12 2c 4a 68 bd 28 32 24 5f e5 d8 41 5e ce 74 87 59 63 e0 ec b5 2a 46 ca 97 f9 15 2a 47 1e 6a bf 7e 73 a1 6c 88 70 79 05 4d 6a 35 b7 f2 35 83 8c dd 8f 7f 88 83 71 c4 83 d2 3b f5 70 0e 9b 2e 1d c6 55 58 c9 cd d1 ad e9 9f d2 de 06 34 c6 dc 50 f3 7a dc 1f ed 43 c8 0e 02 d8 38 fe cf 90 c0 6d 3c f8 45 cf 66 0f 21 34 48 8b a8 62 4f fe 60 6c c3 8c 0a 86 15 79 d8 9c 57 71 7a 27 95 60 6f df af fd 03 9e 8a ad 73 b6 b4 2a cf 03 5a a0 e5 92 7a f0 ea 5a e2 a4 c3 f0 b1 1f fe cb fd 40 10 3e b8 c7 54 8c 7a ad 1e 11 4d 0a 41 de 33 35 f1 96 26 19 91 61 13 0f 45 30 4c ec 4e 4e 46 bf 87 8d 42 bc 71 fd a2 f5 3e a8 5d e1 bc f5 aa f4 8b 65 57 d7 eb 24 1a c1 a6 a6 0e 1d ae 2f 4a 22 96 8f b3 02 03 01 00 01 a3 82 02 4b 30 82 02 47 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 01 06 08 2b 06 01 05 05 07 03 02 30 0c 06 03 55 1d 13 01 01 ff 04 02 30 00 30 1d 06 03 55 1d 0e 04 16 04 14 50 96 b7 26 5e 41 94 57 95 73 97 13 9f 37 d3 9b e6 37 f3 9f 30 1f 06 03 55 1d 23 04 18 30 16 80 14 14 2e b3 17 b7 58 56 cb ae 50 09 40 e6 1f af 9d 8b 14 c2 c6 30 55 06 08 2b 06 01 05 05 07 01 01 04 49 30 47 30 21 06 08 2b 06 01 05 05 07 30 01 86 15 68 74 74 70 3a 2f 2f 72 33 2e 6f 2e 6c 65 6e 63 72 2e 6f 72 67 30 22 06 08 2b 06 01 05 05 07 30 02 86 16 68 74 74 70 3a 2f 2f 72 33 2e 69 2e 6c 65 6e 63 72 2e 6f 72 67 2f 30 1a 06 03 55 1d 11 04 13 30 11 82 0f 76 65 72 62 61 6c 2e 64 64 6e 73 2e 6e 65 74 30 4c 06 03 55 1d 20 04 45 30 43 30 08 06 06 67 81 0c 01 02 01 30 37 06 0b 2b 06 01 04 01 82 df 13 01 01 01 30 28 30 26 06 08 2b 06 01 05 05 07 02 01 16 1a 68 74 74 70 3a 2f 2f 63 70 73 2e 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67 30 82 01 05 06 0a 2b 06 01 04 01 d6 79 02 04 02 04 81 f6 04 81 f3 00 f1 00 77 00 7a 32 8c 54 d8 b7 2d b6 20 ea 38 e0 52 1e e9 84 16 70 32 13 85 4d 3b d2 2b c1 3a 57 a3 52 eb 52 00 00 01 84 8f 65 8a 5a 00 00 04 03 00 48 30 46 02 21 00 86 16 33 ad de 24 6a 97 36 68 f0 dd 05 70 32 01 8b b3 65 60 b4 47 58 5a fa 8d 63 d5 32 08 14 15 02 21 00 c4 53 c5 0c 6a 5f 2f fa ae eb 0f 6f bb ff 7e d1 73 7b 1d 8a a3 27 8f 45 0b f3 e8 da 37 c8 a8 e3 00 76 00 ad f7 be fa 7c ff 10 c8 8b 9d 3d 9c 1e 3e 18 6a b4 67 29 5d cf b1 0c 24 ca 85 86 34 eb dc 82 8a 00 00 01 84 8f 65 8a e3 00 00 04 03 00 47 30 45 02 21 00 99 a1 26 80 6b 39 fd 2e ee 0d 7e 7f f4 62 7b 6a 6f b3 b5 e2 d9 d9 98 e6 18 d9 80 10 42 b0 8c c5 02 20 46 98 a5 01 bf 4e f5 5d 49 45 da a0 ed 30 75 ce 22 70 57 51 ad ff 0e e4 07 b3 6b a9 84 71 01 12 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 47 02 82 d7 8a f5 6a bc 0a 2a 22 5d 3b 12 99 3e 00 ba be 73 58 db 09 b1 5a fd 08 56 75 51 6f 20 50 d4 47 1c fb e8 21 44 a3 a2 08 01 ee d8 19 c4 a0 57 59 44 4f 99 57 65 ad c9 a8 26 11 e9 aa 71 de 49 71 35 45 4f 53 d0 80 c5 b0 c7 85 8c 73 aa 95 66 b8 24 f2 d0 56 50 c0 78 da b6 d2 f3 7b 57 74 8d db 51 0a 55 cf b5 dc 1a 87 06 82 b6 cc 59 11 bf 80 e3 52 28 63 be 35 8f e4 ac 4f 92 78 91 38 ef b0 a9 64 66 d2 85 1b da 91 79 ac 34 a3 f3 8b e5 52 c5 7d e2 b6 24 b8 74 0c d5 d9 fe 2e a3 eb a4 b7 fe 9c 9f 1d b0 c6 98 a9 6e 87 74 57 ea 46 78 aa 87 d8 c0 41 b1 43 f4 d0 d8 dd 57 16 e9 19 81 c9 16 d8 ac 02 40 f5 2b 50 fa 86 87 8e fe 4d ab 1c 71 ae 8d 61 ff 9c 03 b5 f3 6c ec 5d 8f fc 35 53 90 fc 51 b0 ba c9 c3 07 de 70 84 b1 8c 48 cb 94 2c 33 d0 26 d5 08 bd 0c ba 80 1b 23 f5"_hex();
        static const ByteStream serverEncryptedExt{0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
        static const ByteStream serverCertificate = ByteStream{0x0b} | ByteStreamFromUintBE<24>(certBuffer.size() + 9) | 
                                                    ByteStream{0x00} | ByteStreamFromUintBE<24>(certBuffer.size() + 5) |
                                                    ByteStreamFromUintBE<24>(certBuffer.size()) | certBuffer |
                                                    ByteStream{0x00, 0x00};

        using namespace std::chrono;
        ByteStream serverVerify = ByteStream{0x0f, 0x00, 0x01, 0x04, 0x08, 0x04, 0x01, 0x00} | 
                                  RSA_PSS_Sign(
                                    ByteStream(64, ' ') | // 64 space character
                                    ByteStreamFromString("TLS 1.3, server CertificateVerify") | 
                                    ByteStream{0x00} |
                                    Hash::SHA256(clientHello | serverHello | serverEncryptedExt | serverCertificate)
                                  );
        auto finishedKey = HKDF_Expand_Label(handshakeKey.server_handshake_traffic_secret, "finished", ByteStream{}, 32);
        auto finishedHash = Hash::SHA256(clientHello | serverHello | serverEncryptedExt | serverCertificate | serverVerify);
        const ByteStream serverFinished = ByteStream{0x14, 0x00, 0x00, 0x20} | Hash::HMAC_SHA256(finishedKey, finishedHash);

        const ByteStream serverHandshakeInfo = serverEncryptedExt | serverCertificate | serverVerify | serverFinished;

        sock.sendByteStream(makeEncryptedRecord(handshakeSend.encrypt(serverHandshakeInfo | ByteStream{0x16}, makeEncryptedHeader(serverHandshakeInfo))));

        {
            AES128_GCM handshakeDecode(handshakeKey.client_handshake_iv, handshakeKey.client_handshake_key);
            assertThrow(sock.readExactly(6) == ByteStream{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}, "client change cipher not valid");
            for (;;) {
                auto header = sock.readExactly(5);
                auto data = sock.readExactly(header[3] << 8 | header[4]);
                auto content = handshakeDecode.decrypt(data, header);
                if (content.back() == 0x16) {
                    auto hash = (ByteStream{0x14, 0x00, 0x00, 0x20} | Hash::HMAC_SHA256(
                        HKDF_Expand_Label(handshakeKey.client_handshake_traffic_secret, "finished", ByteStream{}, 32), 
                        Hash::SHA256(clientHello | serverHello | serverEncryptedExt | serverCertificate | serverVerify | serverFinished)
                    ) | ByteStream{0x16});
                    assertThrow(content == hash, "client finish hash failed");
                    break;
                } else throw std::runtime_error("invalid client finished");
                // else if (content.back() == 0x15) {
                //     if (content.front() == 0x02) 
                //         printf("handshake alert code %d\n", content[1]);
                //     else
                //         printf("handshake what code %d\n", content[1]);
                // }
            }
        }
        ApplicationKey applicationKeys(handshakeKey.handshake_secret, Hash::SHA256(clientHello | serverHello | serverEncryptedExt | serverCertificate | serverVerify | serverFinished));
        decryptor = new AES128_GCM(applicationKeys.client_application_iv, applicationKeys.client_application_key);
        encryptor = new AES128_GCM(applicationKeys.server_application_iv, applicationKeys.server_application_key);
    }

    void readRecord() {
        for (;;) {
            auto header = sock.readExactly(5);
            uint32_t recordSize = header[3] << 8 | header[4];
            assertThrow(recordSize <= (1u << 14) + 17, "record size too big");
            auto response = decryptor->decrypt(sock.readExactly(recordSize), header);
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
            auto encrypted = encryptor->encrypt(message | ByteStream{0x17}, makeEncryptedHeader(message));
            sock.sendByteStream(makeEncryptedRecord(encrypted));
            
            length -= sendLength;
            ptr += sendLength;
        }
    }
    ~TLSClientHandle() {
        delete encryptor; 
        delete decryptor;
    }
private:
    struct FIFO {
        ByteStream const& ref;
        uint32_t ptr;
        FIFO(ByteStream const& value) : ref{value}, ptr{} {}
        uint32_t bytesLeft() const {
            return ref.size() - ptr;
        }
        ByteStream getBytes(uint32_t size) {
            if (size == 0) return ByteStream{};
            assertThrow(bytesLeft() >= size, "Not enough data to read");
            ByteStream result(&ref[ptr], &ref[ptr] + size);
            ptr += size;
            return result;
        }
        template<int bytes>
        uint64_t getBENumber() {
            static_assert(bytes > 0 && bytes <= 8);
            assertThrow(bytesLeft() >= bytes, "Not enough data to read");
            uint64_t value = 0;
            for (int i = 0; i < bytes; ++i) {
                value = value << 8u | ref[ptr + i];
            }
            ptr += bytes;
            return value;
        }
        void eatBytes(uint32_t size) {
            assertThrow(bytesLeft() >= size, "not enough data to eat");
            ptr += size;
        }
    };

    static std::pair<ByteStream, ByteStream> parseClientHello(std::vector<uint8_t> const& buffer) {
        
        FIFO reader(buffer);
        uint8_t handshakeType = reader.getBENumber<1>();
        assertThrow(handshakeType == 0x01, "wrong handshaketype for clienthello");
        uint32_t handshakeSize = reader.getBENumber<3>();
        assertThrow(reader.bytesLeft() == handshakeSize, "wrong client hello handshake size");
        uint32_t legacyVersion = reader.getBENumber<2>();
        assertThrow(legacyVersion == 0x0303, "wrong legacy version");
        reader.eatBytes(32); // 32 bytes random, not used
        uint8_t session_id_length = reader.getBENumber<1>();
        assertThrow(session_id_length == 0 || session_id_length == 32, "invalid session id length");
        ByteStream session_id = reader.getBytes(session_id_length);
       
        {
            uint16_t cipher_suites_length = reader.getBENumber<2>();
            std::vector<uint8_t> cipher_suites = reader.getBytes(cipher_suites_length);
            FIFO suites(cipher_suites);
            bool found_TLS_AES_128_GCM_SHA256 = false;
            while (suites.bytesLeft()) 
                if (suites.getBENumber<2>() == 0x1301) 
                    found_TLS_AES_128_GCM_SHA256 = true;
            
            assertThrow(found_TLS_AES_128_GCM_SHA256, "unsupported cipher suites");
        }
        assertThrow(reader.getBENumber<2>() == 0x0100, "unsupported compression");
        
        uint16_t extensionLength = reader.getBENumber<2>();
        assertThrow(extensionLength == reader.bytesLeft(), "wrong extension length");
        std::unordered_map<uint16_t, ByteStream> contents;
        while (reader.bytesLeft()) {
            uint32_t extType = reader.getBENumber<2>();
            uint16_t extLength = reader.getBENumber<2>();
            assertThrow(contents.insert({ extType, reader.getBytes(extLength) }).second, "duplicated extension");
        }

        {
            bool haveTLS1_3 = false;
            FIFO supportedVersion(contents.at(0x002b));
            uint8_t length = supportedVersion.getBENumber<1>();
            assertThrow(supportedVersion.bytesLeft() == length, "wrong version length");
            while (supportedVersion.bytesLeft())
                if (supportedVersion.getBENumber<2>() == 0x0304)
                    haveTLS1_3 = true;
            assertThrow(haveTLS1_3, "unsupported tls version");
        }
        {
            bool haveRSAPSS = false;
            FIFO signature(contents.at(0x000d));
            uint16_t length = signature.getBENumber<2>();
            assertThrow(signature.bytesLeft() == length, "wrong signature algorithm length");
            while (signature.bytesLeft()) {
                if (signature.getBENumber<2>() == 0x0804)
                    haveRSAPSS = true;
            }
            assertThrow(haveRSAPSS, "don't have RSAPSS");
        }
        ByteStream otherPublicKey;
        {
            FIFO keyShare(contents.at(0x0033));
            uint16_t keyShareLength = keyShare.getBENumber<2>();
            assertThrow(keyShareLength == keyShare.bytesLeft(), "key share length wrong");
            while (keyShare.bytesLeft()) {
                uint16_t group = keyShare.getBENumber<2>();
                uint16_t length = keyShare.getBENumber<2>();
                keyShareLength -= 4 + length;
                if (group != 0x001d) {
                    keyShare.eatBytes(length);
                    continue;
                }
                assertThrow(length == 32, "key share length of curve x25519 must be 32");
                otherPublicKey = keyShare.getBytes(32);
            }
            assertThrow(!otherPublicKey.empty(), "don't have curvex25519 key exchange");
        }
        return std::make_pair(std::move(session_id), std::move(otherPublicKey));
    }
    BufferedSocket sock;
    AES128_GCM* decryptor;
    AES128_GCM* encryptor;
    uint8_t readBuffer[16384];
    int ptr, size;
public:
    std::mutex mtx;
};