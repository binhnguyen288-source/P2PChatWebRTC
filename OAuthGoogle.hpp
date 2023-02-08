#pragma once
#include <stdexcept>
#include <iostream>
#include "util/base64.hpp"
#include "json.hpp"
#include "util/TLSClient.hpp"
#include "HTTPUtil.hpp"
// const std::string clientSecret = "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";
// const std::string clientID = "958163678615-99m4jfkf1tih867va4qougkk19ek98qq.apps.googleusercontent.com";

const std::string googleAuthURL = "https://accounts.google.com/o/oauth2/v2/auth?client_id=958163678615-99m4jfkf1tih867va4qougkk19ek98qq.apps.googleusercontent.com&prompt=select_account&redirect_uri=https%3A%2F%2Fverbal.ddns.net%2Flogin%2Fcallback&response_type=code&scope=profile email";
const std::string googleRedirectDomain = "oauth2.googleapis.com";
const std::string googleRedirectQuery = "client_id=958163678615-99m4jfkf1tih867va4qougkk19ek98qq.apps.googleusercontent.com&client_secret=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&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fverbal.ddns.net%2Flogin%2Fcallback";


std::string contactGoogleOAuth(std::string const& code) {

    TLSClient client(googleRedirectDomain.c_str(), "443");
    
    

    std::string query = googleRedirectQuery + "&code=" + code;
    std::string request = "POST /token HTTP/1.1\r\n";
    request += "Host: " + googleRedirectDomain + "\r\n";
    request += "Content-Type: application/x-www-form-urlencoded\r\n";
    request += "Content-Length: " + std::to_string(query.length()) + "\r\n\r\n";
    request += query;

    client.write(request.data(), request.length());

    auto headers = getHTTPHeader(client, 1024, 8192);
    std::string result;
    for (;;) {
        uint32_t chunkLength = std::stoi(readHTTPLine(client, 128), nullptr, 16);
        
        if (chunkLength == 0) {
            client.getByte();
            client.getByte();
            break;
        }
        while (chunkLength--) {
            result.push_back((char)client.getByte());
        }
        client.getByte();
        client.getByte();
    }
    auto json = nlohmann::json::parse(result);

    json = nlohmann::json::parse(Base64URL::decode(split(json.at("id_token").get<std::string>(), '.')[1]));


    nlohmann::json user_info{
        {"fullname", json.at("name")},
        {"id", json.at("email")},
        {"picture", json.at("picture")}
    };
    
    return user_info.dump();
}