#include "TLS_TCPServer.hpp"
#include "OAuthGoogle.hpp"
#include "HTTPUtil.hpp"
#include <fstream>
#include <thread>
#include <sstream>
#include "jwt_secret.hpp"
#include "mysql.hpp"
#include <mutex>
#include "formatstr.hpp"

std::string readTextFile(std::string filename) {
    std::ifstream file(filename);
    std::ostringstream stream;
    stream << file.rdbuf();
    return stream.str();
}

using Headers = std::unordered_map<std::string, std::string>;


auto getUserId(Headers const& headers) {
    try {
        auto splitted = split(split(headers.at("Cookie"), '=')[1], '.');
        auto payload = splitted[0];
        auto signature = Base64URL::encode(Hash::HMAC_SHA256(JWT_SECRET, payload));
        assertThrow(signature == splitted[1], "signature failed");
        auto json = nlohmann::json::parse(Base64URL::decode(payload));
        
        return std::make_tuple(json.at("id").get<std::string>(), json.at("fullname").get<std::string>(), json.at("picture").get<std::string>());
    } catch (...) {
        return std::make_tuple(std::string(), std::string(), std::string());
    }
}
#include "sqlite.hpp"
struct ThreadSafeDriver {
    SQLiteDriver driver;
    std::mutex mtx;

    ThreadSafeDriver() : driver("database.db") {}

    auto sendQuery(std::string const& v) {
        std::scoped_lock lck(mtx);
        return driver.query(v);
    }
    auto sendModify(std::string const& v) {
        std::scoped_lock lck(mtx);
        return driver.query(v);
    }
};

std::unique_ptr<ThreadSafeDriver> db;


void handle_client(std::unique_ptr<TLSClientHandle> client) {
    try {
        const HTTPRequestType requestType = HTTPRequestType::get(*client);
        const Headers headers = getHTTPHeader(*client, 1024, 8192);

        
        
        if (requestType.path.starts_with("/login/callback")) {
            auto queries = getHTTPQuery(requestType.path);
            std::string json_str = contactGoogleOAuth(queries.at("code"));
            auto payload = Base64URL::encode(json_str);
            auto signature = Base64URL::encode(Hash::HMAC_SHA256(JWT_SECRET, payload));
            std::string cookie = payload + '.' + signature;
            std::string response = "HTTP/1.1 302 Found\r\n";
            response += "Set-Cookie: cookie=" + cookie + "; Max-Age=3600; Secure; HttpOnly; Path=/\r\n";
            response += "Location: /\r\n\r\n";
            client->write(response.data(), response.length());
            return;
        }
        auto [userId, fullname, picture] = getUserId(headers);
        

        if (userId.empty()) {
            std::string response = "HTTP/1.1 302 Found\r\nLocation: " + googleAuthURL + "\r\nConnection: close\r\n\r\n";
            client->write(response.data(), response.length());
            return;
        }
        
        db->sendModify(format(R"(INSERT or IGNORE INTO userinfo (id,fullname,picture) VALUES ("{}","{}","{}"))", userId, fullname, picture));
        
        if (requestType.path == "/favicon.ico") {
            std::string response = "HTTP/1.1 200 OK\r\n\r\n";
            client->write(response.data(), response.length());
            return;
        }
        if (requestType.path.starts_with("/public")) {
            
            const std::string content = readTextFile(".." + requestType.path);
            std::string response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: " + getMimeType(requestType.path) + "; charset=UTF-8\r\n";
            response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            response += content;
            client->write(response.data(), response.length());
            return;
        }
        if (requestType.path == "/") {

            const std::string content = readTextFile("../public/index.html");
            std::string response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: text/html; charset=UTF-8\r\n";
            response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            response += content;
            client->write(response.data(), response.length());
            return;
        }
        if (requestType.path == "/getListFriend") {
            const std::string query = format(R"(SELECT id,fullname,picture FROM userinfo JOIN friendshipinfo on id=acceptId WHERE requestId="{}")", userId);
            nlohmann::json json{
                {"id", userId},
                {"fullname", fullname},
                {"picture", picture},
                {"friends", db->sendQuery(query)}
            };
            
            auto content = json.dump();
            std::string response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: application/json; charset=UTF-8\r\n";
            response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            response += content;
            client->write(response.data(), response.length());
            return;
        }
        if (requestType.path.starts_with("/addFriend")) {
            std::string friendEmail = getHTTPQuery(requestType.path).at("id");
            std::string response = "HTTP/1.1 200 OK\r\n\r\n";
            if (!db->sendQuery(format(R"(SELECT id FROM userinfo WHERE id="{}")", friendEmail)).empty()) {
                db->sendModify(format(R"(INSERT or IGNORE INTO friendshipinfo(requestId, acceptId) VALUES ("{}", "{}"), ("{}", "{}"))", userId, friendEmail, friendEmail, userId));
            }
            client->write(response.data(), response.length());
            return;
        }
    } catch (std::exception const& e) {
        std::cout << e.what() << std::endl;
    } catch (...) {
        std::cout << "Unknown exception" << std::endl;
    }

}

int main() {
    InitSocketLib();
    db = std::make_unique<ThreadSafeDriver>();
    db->sendModify("CREATE TABLE IF NOT EXISTS userinfo(id VARCHAR(320) NOT NULL PRIMARY KEY, fullname TEXT NOT NULL, picture TEXT NOT NULL);"
                   "CREATE TABLE IF NOT EXISTS friendshipinfo(requestId VARCHAR(320) NOT NULL, acceptId VARCHAR(320) NOT NULL, PRIMARY KEY (requestId, acceptId));");
    TLS_TCPServer server(8080);
    for (;;) {
        std::unique_ptr<TLSClientHandle> client{server.accept()};
        std::thread worker(handle_client, std::move(client));
        worker.detach();
    }
    CleanupSocketLib();
    return 0;
}