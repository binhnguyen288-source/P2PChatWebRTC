#pragma once
#include "HKDF.hpp"
#include "SHA256.hpp"


struct HandshakeKey {
    ByteStream derived_secret;
    ByteStream handshake_secret;
    ByteStream client_handshake_traffic_secret; 
    ByteStream server_handshake_traffic_secret; 
    ByteStream client_handshake_key; 
    ByteStream server_handshake_key; 
    ByteStream client_handshake_iv; 
    ByteStream server_handshake_iv; 
    HandshakeKey(ByteStream const& shared_secret, ByteStream const& hello_hash);
};

struct ApplicationKey {
    // ByteStream derived_secret;
    // ByteStream master_secret;
    // ByteStream client_application_traffic_secret; 
    // ByteStream server_application_traffic_secret; 
    ByteStream client_application_key; 
    ByteStream server_application_key; 
    ByteStream client_application_iv; 
    ByteStream server_application_iv; 
    ApplicationKey(ByteStream const& handshake_secret, ByteStream const& handshake_hash);
};

void keyCalcTest();