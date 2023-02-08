#pragma once
#include "util/socket.hpp"
#include "util/ByteStream.hpp"
#include <unordered_map>




struct MySQLDriver {
    BufferedSocket driver;
    MySQLDriver(const char* serverIp, const char* port, std::string const& user, std::string const& db) : driver(serverIp, port) {
        

        driver.readExactly(5);
        while (driver.getByte() != 0);
        driver.readExactly(4);
        auto auth1 = driver.readExactly(8);
        driver.readExactly(8);
        uint8_t auth2size = driver.getByte();
        driver.readExactly(10);
        auto auth2 = driver.readExactly(auth2size - 8);
        std::string auth_method;
        char c;
        while ((c = driver.getByte())) auth_method.push_back(c);


        ByteStream handshake_response = ByteStreamFromUintLE<32>(0x00000200 | 0x00020000 | 0x00000008 | 0x1000000) | // capability
                                        ByteStreamFromUintLE<32>(1 << 24) | // length
                                        ByteStream{0x33} | ByteStream(23, 0) | // charset utf8 
                                        ByteStreamFromString(user) | ByteStream{0x00} | // username
                                        ByteStream{0x00} | // password
                                        ByteStreamFromString(db) | ByteStream{0x00} | // database
                                        ByteStream{0x00}; // compression 0
                                
        driver.sendByteStream(ByteStreamFromUintLE<24>(handshake_response.size()) | ByteStream{0x01} | handshake_response);
        if (MySQLDriver::readResponse(driver).front() != 0x00) 
            throw std::runtime_error("connect to database failed");
    }
    static ByteStream readResponse(BufferedSocket& driver) {
        uint32_t size = driver.getUintLE<32>() & 0x00ff'ffff;
        return driver.readExactly(size);
    }
        

    uint64_t readEncodedLengthInteger() {
        uint64_t value = driver.getByte();
        switch (value) {
            case 0xfc: return driver.getUintLE<16>();
            case 0xfd: return driver.getUintLE<24>();
            case 0xfe: return driver.getUintLE<64>();
        }
        return value;
    }

    uint8_t sendModify(std::string const& query) {
        driver.sendByteStream(ByteStreamFromUintLE<24>(query.length() + 1) | ByteStream{0x00, 0x03} | ByteStreamFromString(query));
        return readResponse(driver)[0];
    }

    std::vector<std::unordered_map<std::string, std::string>> sendQuery(std::string const& query) {
        driver.sendByteStream(ByteStreamFromUintLE<24>(query.length() + 1) | ByteStream{0x00, 0x03} | ByteStreamFromString(query));

        uint8_t nColumns = readResponse(driver)[0];
        if (nColumns >= 0xfb)
            throw std::runtime_error("failed query");
        if (nColumns == 0) 
            return {};
        
        std::vector<std::string> columns;
        std::vector<std::unordered_map<std::string, std::string>> result;
        
        for (int i = 0; i < nColumns; ++i) {
            uint32_t sizeLeft = driver.getUintLE<32>() & 0x00ff'ffff;
            for (int i = 0; i < 5; ++i) {
                int fieldSize = driver.getByte();
                driver.readExactly(fieldSize);
                sizeLeft -= 1 + fieldSize;
            }
            int column_size = driver.getByte();
            auto column_name = driver.readExactly(column_size);
            columns.push_back(std::string(column_name.begin(), column_name.end()));
            driver.readExactly(sizeLeft - column_size - 1);
        }
        for (;;) {
            const uint32_t sizeLeft = driver.getUintLE<32>() & 0x00ff'ffff;
            if (driver.getByte<true>() == 0xfe && sizeLeft < 9) {
                // eof packet
                driver.readExactly(sizeLeft);
                break;
            }
            result.emplace_back();
            for (std::string const& col : columns) {
                uint64_t size = readEncodedLengthInteger();
                auto value = driver.readExactly(size);
                result.back().insert({ col, std::string(value.begin(), value.end())});
            }
        }
        return result;
    }
    ~MySQLDriver() {
        driver.sendByteStream(ByteStream{0x01, 0x00, 0x00, 0x00, 0x01});
    }
};