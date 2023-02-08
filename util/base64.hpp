#pragma once
#include <string>
#include <cstdlib>
#include <vector>

namespace Base64 {
        
    const std::string base64_chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";


    inline bool is_base64(uint8_t c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }


    std::string encode(uint8_t const* buf, unsigned int bufLen) {
        std::string ret;
        int i = 0;
        int j = 0;
        uint8_t char_array_3[3];
        uint8_t char_array_4[4];

        while (bufLen--) {
            char_array_3[i++] = *(buf++);
            if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
            }
        }

        if (i)
        {
            for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

            while((i++ < 3))
            ret += '=';
        }

        return ret;
    }
}




namespace Base64URL {
const char base64_url_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};


std::string encode(const std::string & in) {
  std::string out;
  int val =0, valb=-6;
  size_t len = in.length();
  unsigned int i = 0;
  for (i = 0; i < len; i++) {
    unsigned char c = in[i];
    val = (val<<8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
  }
  return out;
}

std::string encode(const std::vector<uint8_t>& in) {
  return encode(std::string(in.begin(), in.end()));
}

std::string decode(const std::string & in) {
  std::string out;
  std::vector<int> T(256, -1);
  unsigned int i;
  for (i =0; i < 64; i++) T[base64_url_alphabet[i]] = i;

  int val = 0, valb = -8;
  for (i = 0; i < in.length(); i++) {
    unsigned char c = in[i];
    if (T[c] == -1) break;
    val = (val<<6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val>>valb)&0xFF));
      valb -= 8;
    }
  }
  return out;
}
}