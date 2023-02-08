#pragma once
#include <string>
#include <sstream>

template<typename T>
void format_helper(
    std::ostringstream& oss,
    std::string_view& str, 
    const T& value
) {
    std::size_t openBracket = str.find('{');
    if (openBracket == std::string::npos) { return; }
    std::size_t closeBracket = str.find('}', openBracket + 1);
    if (closeBracket == std::string::npos) { return; }
    if (value.find('"') != std::string::npos)
        throw std::runtime_error("invalid character");
    oss << str.substr(0, openBracket) << value;
    str = str.substr(closeBracket + 1);
}

template<typename... Targs>
std::string format(std::string_view str, Targs...args) {
    std::ostringstream oss;
    (format_helper(oss, str, args),...);
    oss << str;
    return oss.str();
}