cmake_minimum_required(VERSION 3.22)
project(WebSocketServer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wpedantic -march=native)

add_library(TLSServer STATIC TLS_TCPServer.cpp TLS_TCPServer.hpp)
add_library(curve25519 STATIC crypto/curve25519.cpp crypto/curve25519.hpp)
add_library(SHA STATIC crypto/SHA1.cpp crypto/SHA256.cpp crypto/SHA1.hpp crypto/SHA256.hpp)
add_library(HKDF STATIC crypto/HKDF.cpp crypto/HKDF.hpp)
add_library(RSAPSS STATIC crypto/RSAPSS.cpp crypto/RSAPSS.hpp)
add_library(AESGCM STATIC crypto/aes.cpp crypto/aes_gcm.cpp crypto/aes.hpp crypto/aes_gcm.hpp)
add_library(TLSKeyCalc STATIC crypto/TLSKeyCalc.cpp crypto/TLSKeyCalc.hpp)
add_library(SQLITE3 STATIC sqlite3/sqlite3.c sqlite3/sqlite3.h)

add_executable(http HTTP.cpp)
add_executable(wsSignal WebSocketServer.cpp)


list(APPEND linkingList TLSServer curve25519 RSAPSS SHA AESGCM TLSKeyCalc HKDF SQLITE3)
if (WIN32)
    list(APPEND linkingList -lws2_32)
endif()


target_link_libraries(http ${linkingList})
target_link_libraries(wsSignal ${linkingList})

