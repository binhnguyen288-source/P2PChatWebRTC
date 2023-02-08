#include "TLSKeyCalc.hpp"


static const ByteStream early_secret = HKDF_Extract(ByteStream{}, ByteStream(32));
static const ByteStream empty_hash = Hash::SHA256(ByteStream{});


HandshakeKey::HandshakeKey(ByteStream const& shared_secret, ByteStream const& hello_hash) {
    derived_secret = HKDF_Expand_Label(early_secret, "derived", empty_hash, 32);
    handshake_secret = HKDF_Extract(derived_secret, shared_secret);
    client_handshake_traffic_secret = HKDF_Expand_Label(handshake_secret, "c hs traffic", hello_hash, 32);
    server_handshake_traffic_secret = HKDF_Expand_Label(handshake_secret, "s hs traffic", hello_hash, 32);
    client_handshake_key = HKDF_Expand_Label(client_handshake_traffic_secret, "key", ByteStream{}, 16);
    server_handshake_key = HKDF_Expand_Label(server_handshake_traffic_secret, "key", ByteStream{}, 16);
    client_handshake_iv = HKDF_Expand_Label(client_handshake_traffic_secret, "iv", ByteStream{}, 12);
    server_handshake_iv = HKDF_Expand_Label(server_handshake_traffic_secret, "iv", ByteStream{}, 12);
}


ApplicationKey::ApplicationKey(ByteStream const& handshake_secret, ByteStream const& handshake_hash) {
    ByteStream derived_secret = HKDF_Expand_Label(handshake_secret, "derived", empty_hash, 32);
    ByteStream master_secret = HKDF_Extract(derived_secret, ByteStream(32));
    ByteStream client_application_traffic_secret = HKDF_Expand_Label(master_secret, "c ap traffic", handshake_hash, 32);
    ByteStream server_application_traffic_secret = HKDF_Expand_Label(master_secret, "s ap traffic", handshake_hash, 32);
    client_application_key = HKDF_Expand_Label(client_application_traffic_secret, "key", ByteStream{}, 16);
    server_application_key = HKDF_Expand_Label(server_application_traffic_secret, "key", ByteStream{}, 16);
    client_application_iv = HKDF_Expand_Label(client_application_traffic_secret, "iv", ByteStream{}, 12);
    server_application_iv = HKDF_Expand_Label(server_application_traffic_secret, "iv", ByteStream{}, 12);
}


// test down here
#include <stdexcept>
#include "../util/hexutil.hpp"
#include "curve25519.hpp"
#include <iostream>
static void expectEqual(ByteStream const& value, ByteStream const& expected, const char* msg = "assert equal failed") {
    if (value != expected)
        throw std::runtime_error(msg);
}


void keyCalcTest() {

    constexpr auto clientHello = "01 00 00 c6 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 06 13 01 13 02 13 03 01 00 00 77 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04"_hex;
    constexpr auto serverHello = "02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 01 00 00 2e 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15 00 2b 00 02 03 04"_hex;
    constexpr auto clientKey = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"_hex;
    constexpr auto serverKey = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"_hex;
    ByteStream shared_secret = mulKeys(serverKey(), clientKey());
    expectEqual(shared_secret, "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624"_hex());
    
    constexpr auto hello = clientHello + serverHello;
    ByteStream hello_hash = Hash::SHA256(hello());
    expectEqual(hello_hash, "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5"_hex());

    auto [
        derived_secret,
        handshake_secret,
        client_handshake_traffic_secret,
        server_handshake_traffic_secret,
        client_handshake_key,
        server_handshake_key,
        client_handshake_iv,
        server_handshake_iv
    ] = HandshakeKey(shared_secret, hello_hash);
    expectEqual(handshake_secret, "fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a"_hex());
    expectEqual(client_handshake_traffic_secret, "ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea"_hex());
    expectEqual(server_handshake_traffic_secret, "a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814"_hex());
    expectEqual(client_handshake_key, "7154f314e6be7dc008df2c832baa1d39"_hex());
    expectEqual(server_handshake_key, "844780a7acad9f980fa25c114e43402a"_hex());
    expectEqual(client_handshake_iv, "71abc2cae4c699d47c600268"_hex());
    expectEqual(server_handshake_iv, "4c042ddc120a38d1417fc815"_hex());
    {
        ByteStream handshake_hash = "22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b"_hex();
        auto [
            client_application_key,
            server_application_key,
            client_application_iv,
            server_application_iv
        ] = ApplicationKey(handshake_secret, handshake_hash);
        
        expectEqual(client_application_key, "49134b95328f279f0183860589ac6707"_hex());
        expectEqual(server_application_key, "0b6d22c8ff68097ea871c672073773bf"_hex());
        expectEqual(client_application_iv, "bc4dd5f7b98acff85466261d"_hex());
        expectEqual(server_application_iv, "1b13dd9f8d8f17091d34b349"_hex());
    }

    constexpr auto ext = "08 00 00 02 00 00"_hex;
    constexpr auto cert = "0b 00 03 2e 00 00 03 2a 00 03 25 30 82 03 21 30 82 02 09 a0 03 02 01 02 02 08 15 5a 92 ad c2 04 8f 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 22 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 0a 13 0a 45 78 61 6d 70 6c 65 20 43 41 30 1e 17 0d 31 38 31 30 30 35 30 31 33 38 31 37 5a 17 0d 31 39 31 30 30 35 30 31 33 38 31 37 5a 30 2b 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 1c 30 1a 06 03 55 04 03 13 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 c4 80 36 06 ba e7 47 6b 08 94 04 ec a7 b6 91 04 3f f7 92 bc 19 ee fb 7d 74 d7 a8 0d 00 1e 7b 4b 3a 4a e6 0f e8 c0 71 fc 73 e7 02 4c 0d bc f4 bd d1 1d 39 6b ba 70 46 4a 13 e9 4a f8 3d f3 e1 09 59 54 7b c9 55 fb 41 2d a3 76 52 11 e1 f3 dc 77 6c aa 53 37 6e ca 3a ec be c3 aa b7 3b 31 d5 6c b6 52 9c 80 98 bc c9 e0 28 18 e2 0b f7 f8 a0 3a fd 17 04 50 9e ce 79 bd 9f 39 f1 ea 69 ec 47 97 2e 83 0f b5 ca 95 de 95 a1 e6 04 22 d5 ee be 52 79 54 a1 e7 bf 8a 86 f6 46 6d 0d 9f 16 95 1a 4c f7 a0 46 92 59 5c 13 52 f2 54 9e 5a fb 4e bf d7 7a 37 95 01 44 e4 c0 26 87 4c 65 3e 40 7d 7d 23 07 44 01 f4 84 ff d0 8f 7a 1f a0 52 10 d1 f4 f0 d5 ce 79 70 29 32 e2 ca be 70 1f df ad 6b 4b b7 11 01 f4 4b ad 66 6a 11 13 0f e2 ee 82 9e 4d 02 9d c9 1c dd 67 16 db b9 06 18 86 ed c1 ba 94 21 02 03 01 00 01 a3 52 30 50 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 01 30 1f 06 03 55 1d 23 04 18 30 16 80 14 89 4f de 5b cc 69 e2 52 cf 3e a3 00 df b1 97 b8 1d e1 c1 46 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 59 16 45 a6 9a 2e 37 79 e4 f6 dd 27 1a ba 1c 0b fd 6c d7 55 99 b5 e7 c3 6e 53 3e ff 36 59 08 43 24 c9 e7 a5 04 07 9d 39 e0 d4 29 87 ff e3 eb dd 09 c1 cf 1d 91 44 55 87 0b 57 1d d1 9b df 1d 24 f8 bb 9a 11 fe 80 fd 59 2b a0 39 8c de 11 e2 65 1e 61 8c e5 98 fa 96 e5 37 2e ef 3d 24 8a fd e1 74 63 eb bf ab b8 e4 d1 ab 50 2a 54 ec 00 64 e9 2f 78 19 66 0d 3f 27 cf 20 9e 66 7f ce 5a e2 e4 ac 99 c7 c9 38 18 f8 b2 51 07 22 df ed 97 f3 2e 3e 93 49 d4 c6 6c 9e a6 39 6d 74 44 62 a0 6b 42 c6 d5 ba 68 8e ac 3a 01 7b dd fc 8e 2c fc ad 27 cb 69 d3 cc dc a2 80 41 44 65 d3 ae 34 8c e0 f3 4a b2 fb 9c 61 83 71 31 2b 19 10 41 64 1c 23 7f 11 a5 d6 5c 84 4f 04 04 84 99 38 71 2b 95 9e d6 85 bc 5c 5d d6 45 ed 19 90 94 73 40 29 26 dc b4 0e 34 69 a1 59 41 e8 e2 cc a8 4b b6 08 46 36 a0 00 00"_hex;
    auto handshake_hash = Hash::SHA256((clientHello + serverHello + ext + cert)());
    expectEqual(handshake_hash, "3e66361ada42c7cb97f9a62b00cae1d8b584174c745f9a338cf9f7cdd51d15f8"_hex());
    std::cout << "All test passed" << std::endl;
}