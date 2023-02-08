#pragma once
#include <string>
#include <vector>
#include <unordered_map>



inline std::vector<std::string> split(std::string const& str, char sep) {
    std::vector<std::string> result;
    std::string cur;
    for (char c : str) {
        if (c == sep) {
            result.push_back(std::move(cur));
            cur.clear();
            continue;
        }
        cur.push_back(c);
    }
    result.push_back(cur);
    return result;
}



inline std::unordered_map<std::string, std::string> getHTTPQuery(std::string const& path) {

    auto questionMarkPos = path.find('?');
    if (questionMarkPos == std::string::npos)
        throw std::runtime_error("Invalid query");

    std::unordered_map<std::string, std::string> result;

    auto splittedAnd = split(path.substr(questionMarkPos + 1), '&');
    for (auto const& part : splittedAnd) {
        auto equalPos = part.find('=');
        if (equalPos == std::string::npos)
            throw std::runtime_error("Invalid query");
        result.insert({
            part.substr(0, equalPos), part.substr(equalPos + 1)
        });
    }


    return result;

}

struct HTTPRequestType {
    std::string method;
    std::string path;
    template<typename T>
    static HTTPRequestType get(T& reader) {
        std::vector<std::string> splitted = split(readHTTPLine(reader, 1024), ' ');
        if (splitted.size() == 3 && splitted[0] == "GET") {
            return {splitted[0], splitted[1]};
        }
        throw std::runtime_error("Invalid http method");
    }
};



template<typename T>
std::string readHTTPLine(T& reader, const size_t maxPerLine) {
    std::string result;
    char c;
    while ((c = (char)reader.getByte()) != '\r') {
        result.push_back(c);
        if (result.length() > maxPerLine) 
            throw std::runtime_error("Invalid HTTP request: Too long line.");
    }

    if ((char)reader.getByte() != '\n')
        std::runtime_error("Invalid HTTP request: Invalid line termination.");
    
    return result;
}




#include <iostream>
template<typename T>
std::unordered_map<std::string, std::string> getHTTPHeader(T& reader, const size_t maxLines = 1024, const size_t maxPerLine = 8192) {
    std::unordered_map<std::string, std::string> result;

    size_t totalLine = 0;
    for (;;) {
        ++totalLine;
        if (totalLine >= maxLines) 
            throw std::runtime_error("Invalid HTTP request: Too many lines.");
        std::string curLine = readHTTPLine(reader, maxPerLine);
        if (curLine.empty()) break;
        auto sep_pos = curLine.find(':');
        if (sep_pos == std::string::npos) continue;
        result.insert({ curLine.substr(0, sep_pos), curLine.substr(sep_pos + 2)});
    }



    return result;
}

std::string getMimeType(std::string_view path) {
    if (path.ends_with("css")) {
        return "text/css";
    }
    if (path.ends_with("js")) {
        return "application/javascript";
    }
    if (path.ends_with("html")) {
        return "text/html";
    }
    throw std::runtime_error("invalid file type");
}