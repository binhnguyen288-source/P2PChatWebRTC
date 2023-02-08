#include "RSAPSS.hpp"
#include "SHA256.hpp"
#include "../util/hexutil.hpp"
#include <cstring>
#include <algorithm>
static inline uint64_t add_carry(uint64_t a, uint64_t b, uint8_t& carry) {
    __uint128_t result = (__uint128_t)a + b + carry;
    carry = result >> 64;
    return result;
}

static inline uint64_t sub_borrow(uint64_t a, uint64_t b, uint8_t& borrow) {
    __uint128_t result = (__uint128_t)a - b - borrow;
    borrow = result >> 127;
    return result;
}
#include <array>
template<int words>
struct BigInt {
    std::array<uint64_t, words> value;
    BigInt() : value{} {};

    BigInt(uint64_t low) : BigInt() {
        value[0] = low;
    }
    BigInt(std::vector<uint8_t> const& init, bool littleEndian) : BigInt() {
        auto copy = init;

        if (!littleEndian) std::reverse(copy.begin(), copy.end());
        std::memcpy(value.data(), copy.data(), copy.size());
    }
    BigInt(ByteArray init, bool littleEndian) : BigInt() {
        if (!littleEndian) std::reverse(init.value, init.value + init.length);
        std::memcpy(value.data(), init.value, init.length);
    }


    ByteStream toByteStream256() {
        ByteStream result(256);
        std::memcpy(result.data(), value.data(), result.size());
        std::reverse(result.begin(), result.end());
        return result;
    }
    BigInt operator+(BigInt const& other) const {
        BigInt result;
        uint8_t carry = 0;
        for (int i = 0; i < words; ++i) {
            result.value[i] = add_carry(value[i], other.value[i], carry);
        }
        return result;
    }

    BigInt operator-(BigInt const& other) const {
        BigInt result;
        uint8_t borrow = 0;
        for (int i = 0; i < words; ++i) {
            result.value[i] = sub_borrow(value[i], other.value[i], borrow);
        }
        return result;
    }
    
    BigInt& operator-=(BigInt const& other) {
        uint8_t borrow = 0;
        for (int i = 0; i < words; ++i) {
            value[i] = sub_borrow(value[i], other.value[i], borrow);
        }
        return *this;
    }
    BigInt& operator>>=(int shift) {
        for (int i = 0; i < words; ++i) {
            value[i] = i + shift < words ? value[i + shift] : 0;
        }
        return *this;
    }

    bool operator<(BigInt const& other) const {
        for (int i = words - 1; i > 0; --i) {
            if (value[i] == other.value[i]) continue;
            return value[i] < other.value[i];
        }
        return value[0] < other.value[0];
    }
    bool is_ith_bit_set(uint32_t i) const {
        return (value[i / 64] >> (i % 64)) & 1;
    }
};
constexpr uint32_t RSA_SIZE = 2048;
constexpr int words = 65;
using Uint4096 = BigInt<words>;
//static const Uint4096 modulus("00c31c34d39b899217c83d46b152776f23f6bf7e5eb5a0e6e1c0d11e5578bb66122c4a68bd2832245fe5d8415ece74875963e0ecb52a46ca97f9152a471e6abf7e73a16c887079054d6a35b7f235838cdd8f7f888371c483d23bf5700e9b2e1dc65558c9cdd1ade99fd2de0634c6dc50f37adc1fed43c80e02d838fecf90c06d3cf845cf660f2134488ba8624ffe606cc38c0a861579d89c57717a2795606fdfaffd039e8aad73b6b42acf035aa0e5927af0ea5ae2a4c3f0b11ffecbfd40103eb8c7548c7aad1e114d0a41de3335f19626199161130f45304cec4e4e46bf878d42bc71fda2f53ea85de1bcf5aaf48b6557d7eb241ac1a6a60e1dae2f4a22968fb3"_hex, false);
static const Uint4096 monp("1137cf13778c5ea7f113b840f57bd8a8b9e6a0680386c9da1400fce73192c3ce66ea84a080ed16323ecfd5c17daaf118574f6634ad143c51867c04d1e9fdc6738b7905276b072cfd311afb790c0e080e009ab3cbdaf84edc1c6100ed13e37a873358f0a7e97669b2f932393aaf1ce6dd11a61a3d557c76ca7c0e65ca3815e9f3"_hex, false);
static const Uint4096 monp_big("6d390b3afa280166a07f0ae17c1006238d92b5c5a7233c9a11c59af9e1270ed54f1af6e6494dc4f3c027b1f00cdebac1e0079e04465c3f31cee6d91e9ed579d30b43f37d1be96de29dbeeed3837d2604d9d28325698fd0edf08e056524189142993ba62fffb6546e02e69b4bf1243326d67c040499551b5c5ee1fb3c662700601137cf13778c5ea7f113b840f57bd8a8b9e6a0680386c9da1400fce73192c3ce66ea84a080ed16323ecfd5c17daaf118574f6634ad143c51867c04d1e9fdc6738b7905276b072cfd311afb790c0e080e009ab3cbdaf84edc1c6100ed13e37a873358f0a7e97669b2f932393aaf1ce6dd11a61a3d557c76ca7c0e65ca3815e9f3"_hex, false);
static const Uint4096 r2modp_big("d058832659414ab69e7232837935d8cdcbceb549c61f766638d81923ddc02addff6412509f846c47c71a3a4500ed6a8aa182186af8559d770ef1e4c4dbc9b14eeeeff61dd9d33eca70c2dac7a505724e70627e9696d655b57339dceba531edb47ffb12623c7398cc188cb519a6dbcaae351de72624be1cac18a6bb6526e8cc8c"_hex, false);
static const Uint4096 monq_big("6a7cf6f3416f2d1f1980cba8da8cbcf935232089ca073807ebb48169bec7ce3e097bcd5f345d5055cbc1e55b1b56006eb699884b40c4c661bc289ab26d9756e2843cbdd183d5a81de2686e071439692a9da1fa1e97f51d1521e135c991a2d4be437df3a8f5352358cab4e7cc95599895ffb810d98bc32bef83971881d01cfcee813fe67844eb665b2bea95c1746c9dcbd5def105b59bd60410bf7479a6fc2fe63d7671f79ac836b8556bdba04839c22e7d3dff0f5eeb12c1eb997122ffa46f6e73cdf56058e6fd79721090a1c866096e8a3088ecfc40f391010128a4258e676c18e056d85845ea7b1628105d58e11e5317b6ff2bc0849fb73c1edb5d3a6a9659"_hex, false);
static const Uint4096 r2modq_big("05eafdb2e6f1397a900c01485869302d17a6c12d9435d8d68e8073cf231fe8649f3f2cf75154c1926ae6b16b1f063b7790dacd2b2aad7703058fc5eeac94c48174489e3bc3c0e146763f3fe955531e45004fe36f8a373a81f6f299b1921a6b375308e732be3b1ef238bfd94445f8eb609ee9e9fbfb8e7d1f288707e754c6c0b7"_hex, false);
static const Uint4096 monq("813fe67844eb665b2bea95c1746c9dcbd5def105b59bd60410bf7479a6fc2fe63d7671f79ac836b8556bdba04839c22e7d3dff0f5eeb12c1eb997122ffa46f6e73cdf56058e6fd79721090a1c866096e8a3088ecfc40f391010128a4258e676c18e056d85845ea7b1628105d58e11e5317b6ff2bc0849fb73c1edb5d3a6a9659"_hex, false);
static const Uint4096 r2modp("2d7fc47f0a29d2e743a7c6dea9cf6f26378b2664402e9c3f1b466e32d0ddac58ead90b407141394cf3102d361f4aca68dee11addfcbccd366b40b8c45fe61056a1108c393d917d5977355dbe5ccc4fe65a2cadeb84a9109ee3317898280aff367fdff13e8bbe533843f6aa3ca269bcb0770d5b93a9f0d5162bd0218f6c0de650"_hex, false);
static const Uint4096 r2modq("bf4c8aa2993beeebc94cc4020570b4af192bea5d2ecb576a452887a99f36d4b3033cec849b120353d447e5c2959696ddba457a20022a173e0ff071c351b919b0a25942bf8c7d766c90a46465e58d8088fe94a74effc5954a7138f584b040a1a29e10e31b19c0947f0b5abaf146717a3314722b619a75f3d6cd2cb3be90e61c61"_hex, false);
static const Uint4096 p("00f9e774504f55c359e3f505e3c09353585afb7060908942ce199fb74ecb03ecacb57c074c7b6ccca6f42521abb63e5a52c23105143dc40eae9bba07ca669267bf22aa2301ba8fd323f4b9b52f7cf93d28bab96abf0d0d808f7ec3e8f04d54bc656fa2b4f964dd076afa93ac39be13f9e00d3315a3c87e681015995b08b35728c5"_hex, false);
static const Uint4096 q("00c7de96465f0ba1261960bbcf36146ce8593bdf0931d8ee42d1d32e0bf5ec0a26ee7b9d80fa017881bf9a8460e729c59c3a8d5bd47c23d1ea7c5e0b88c41138d71fe83e81f135b0b0228bcbbb1e25714984267b44508c4d2a3c0378c6cee00cb7e3b926d0696383e1d55703ad18e48114eb0ccb576e60b6baf0afdb1f309cae17"_hex, false);
static const Uint4096 expo1("ddfed7fa879f5e1c3a3e6d6ef6a1694671fc2ec5f95f95b2d45c67505d542d28f747288cae8fe5f4e1a922921120aec819adc61f4707252bc336acb9060944942c4d0b2ffbf4cbd183127d7ba3ff1c6f5400666d35412b554d7ce72ea0e387406cbd131b0098c0802dfc84dffe946c42b6370d202378f72462ab8a8cde13ad29"_hex, false);
static const Uint4096 expo2("8f7d43919de6b178b2bb79d9d74f6ea898779d35f2ad74d04fe736a5ab961bebbb46cfdaaaa1a7ac2eac75e143d3ff649bbca472b5f4d95d688ff3e3ea2f1b098684ab6b8a8a2b21288c08657bcd11b9dfbfe8bb30c0a91d6b1c6af6ffca661716cbf40ba7bda40edba4aea4f4bc07d7c6afd6c41c201ecfb2bfeda644b6175d"_hex, false);
static const Uint4096 qInv("c9c075343592f8a11a0db3973cb6565c42ebac4261ae1fd0ae3fa5297ad9a79b0ab88be9ff668cfea83b2a4c94702a4f59ebfd4d5f99686b13062742deae167d24d92bf6bfa1ec5a656beb23251e37b9c8074c119816e97cae5fdf652893461c0f923f0cb2d2e240890c7a03d402226709d4e0cf77a4731eb018092386de3792"_hex, false);
template<int length>
inline void mulAxB(
    uint64_t const* __restrict a,
    uint64_t const* __restrict b,
    uint64_t* __restrict c
) {
    for (int i = 0; i < length; ++i) {
        __uint128_t carry = 0;
        const uint64_t A = a[i];
        for (int j = 0; j < length; ++j) {
            carry += (__uint128_t)A * b[j] + c[i + j];
            c[i + j] = carry;
            carry >>= 64;
        }
        c[i + length] = carry;
    }
}

template<int length>
inline Uint4096 mulAxB(Uint4096 const& a, Uint4096 const& b) {

    constexpr int lengthWords = (length + 63) / 64;
    static_assert(2 * lengthWords <= 64);
    Uint4096 result{};
    mulAxB<lengthWords>(a.value.data(), b.value.data(), result.value.data());
    return result;
}

template<int size>
static Uint4096 montReduce(Uint4096 const& T, Uint4096 const& modnr, Uint4096 const& mod) {
    Uint4096 m = mulAxB<size>(T, modnr);
    Uint4096 t = mulAxB<size>(m, mod) + T;
    t >>= (size / 64);
    if (!(t < mod)) t -= mod;
    return t;
}

template<int size>
static Uint4096 montMult(Uint4096 const& a, Uint4096 const& b, Uint4096 const& modnr, Uint4096 const& mod) {
    
    constexpr int words = size / 64;
    Uint4096 T{};
    // {
    //     constexpr int dwords = words * 2;
    //     const uint32_t* __restrict A = (uint32_t*)a.value.data();
    //     const uint32_t* __restrict B = (uint32_t*)b.value.data();
    //           uint32_t* __restrict C = (uint32_t*)T.value.data();
    //     for (int i = 0; i < dwords; ++i) {
    //         uint64_t carry = 0;
    //         for (int j = 0; j < dwords; ++j) {
    //             carry += (uint64_t)A[i] * B[j] + C[i + j];
    //             C[i + j] = carry;
    //             carry >>= 32;
    //         }
    //         C[i + dwords] = carry;
    //     }
    // }
    for (int i = 0; i < words; ++i) {
        __uint128_t carry = 0;
        for (int j = 0; j < words; ++j) {
            carry += (__uint128_t)a.value[i] * b.value[j] + T.value[i + j];
            T.value[i + j] = carry;
            carry >>= 64;
        }
        T.value[i + words] = carry;
    }
    Uint4096 m{};
    for (int i = 0; i < words; ++i) {
        __uint128_t carry = 0;
        for (int j = 0; j < words; ++j) {
            if (i + j >= words) break;
            carry += (__uint128_t)T.value[i] * modnr.value[j] + m.value[i + j];
            m.value[i + j] = carry;
            carry >>= 64;
        }
    }
    for (int i = 0; i < words; ++i) {
        __uint128_t carry = 0;
        int j;
        for (j = 0; j < words; ++j) {
            carry += (__uint128_t)m.value[i] * mod.value[j] + T.value[i + j];
            T.value[i + j] = carry;
            carry >>= 64;
        }
        do {
            carry += T.value[i + j];
            T.value[i + j] = carry;
            carry >>= 64;
            ++j;
        } while (carry);
    }
    T >>= words;
    if (!(T < mod)) T -= mod;
    return T; 
   

}

template<int size>
static Uint4096 montgomery_form(Uint4096 const& a, Uint4096 r2mod, Uint4096 const& modnr, Uint4096 const& mod) {
    return montReduce<size>(mulAxB<size>(a, r2mod), modnr, mod);
}


static Uint4096 RSASign(Uint4096 const& message) {

    Uint4096 m1 = montgomery_form<1024>(1, r2modp, monp, p);
    Uint4096 m2 = montgomery_form<1024>(1, r2modq, monq, q);
    {
        int upper = 64 * 64 - 1;
        Uint4096 b = montgomery_form<2048>(message, r2modp_big, monp_big, p);
        b = montReduce<2048>(b, monp_big, p);
        b = montgomery_form<1024>(b, r2modp, monp, p);
        while (!expo1.is_ith_bit_set(upper)) --upper;
        for (int i = 0; i <= upper; ++i) {
            if (expo1.is_ith_bit_set(i))
                m1 = montMult<1024>(m1, b, monp, p);
            b = montMult<1024>(b, b, monp, p);
        }
        m1 = montReduce<1024>(m1, monp, p);
    }
    {
        int upper = 64 * 64 - 1;
        Uint4096 b = montgomery_form<2048>(message, r2modq_big, monq_big, q);
        b = montReduce<2048>(b, monq_big, q);
        b = montgomery_form<1024>(b, r2modq, monq, q);
        while (!expo2.is_ith_bit_set(upper)) --upper;
        for (int i = 0; i <= upper; ++i) {
            if (expo2.is_ith_bit_set(i))
                m2 = montMult<1024>(m2, b, monq, q);
            b = montMult<1024>(b, b, monq, q);
        }
        m2 = montReduce<1024>(m2, monq, q);
    }
    Uint4096 h;
    {
        Uint4096 diff = m1 < m2 ? p + m1 - m2 : m1 - m2;
        diff = montgomery_form<1024>(diff, r2modp, monp, p);
        static const Uint4096 temp = montgomery_form<1024>(qInv, r2modp, monp, p);
        h = montReduce<1024>(mulAxB<1024>(diff, temp), monp, p);
        h = montReduce<1024>(h, monp, p);
    }
    return m2 + mulAxB<1024>(h, q);
}

// Mask generating function 1 according to RFC 8017
static ByteStream MGF1(ByteStream const& seed, uint32_t maskLen) {
    constexpr uint32_t hLen = 32;
    ByteStream T{};
    const uint32_t upper = (maskLen + hLen - 1) / hLen;
    for (uint32_t counter = 0; counter < upper; ++counter) {
        uint32_t be_counter = __builtin_bswap32(counter);
        ByteStream C(4);
        std::memcpy(&C[0], &be_counter, sizeof(be_counter));
        T = T | Hash::SHA256(seed | C);
    }
    T.resize(maskLen);
    return T;
}

// EMSA_PSS_ENCODE according to RFC 8017
static ByteStream EMSA_PSS_ENCODE(ByteStream const& M, uint32_t emBits) {
    constexpr uint32_t sLen = 32;
    constexpr uint32_t hLen = 32;
    int emLen = (emBits + 7) / 8;
    auto mHash = Hash::SHA256(M);
    auto salt = randomByteStream(sLen);
    auto m = ByteStream(8, 0) | mHash | salt;
    auto H = Hash::SHA256(m);
    auto PS = ByteStream(emLen - sLen - hLen - 2, 0);

    auto DB = PS | ByteStream{0x01} | salt;

    auto dbMask = MGF1(H, emLen - hLen - 1);

    ByteStream maskedDB(emLen - hLen - 1);
    for (size_t i = 0; i < maskedDB.size(); ++i) {
        maskedDB[i] = dbMask[i] ^ DB[i];
    }
    // todo set leftmost 
    maskedDB[0] &= 0b1111'1111 >> (8 * emLen - emBits);
    return maskedDB | H | ByteStream{0xbc};
}

ByteStream RSA_PSS_Sign(ByteStream const& message) {
    ByteStream EM = EMSA_PSS_ENCODE(message, RSA_SIZE - 1);
    Uint4096 m(EM, false);
    return RSASign(m).toByteStream256();
}