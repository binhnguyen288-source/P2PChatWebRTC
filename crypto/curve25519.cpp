#include <cstdint>

#include <cstring>
#include <array>
#include <cstdio>
#include <string>
#include <algorithm>
#include <vector>
#include <iostream>
static inline constexpr uint64_t add_carry(uint64_t a, uint64_t b, uint8_t& carry) {
    __uint128_t result = (__uint128_t)a + b + carry;
    carry = result >> 64;
    return result;
}

static inline constexpr uint64_t sub_borrow(uint64_t a, uint64_t b, uint8_t& borrow) {
    __uint128_t result = (__uint128_t)a - b - borrow;
    borrow = result >> 127;
    return result;
}

struct Uint256 {
    uint64_t a[4];
    Uint256() = default;
    constexpr Uint256(uint64_t a0, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0) : 
        a{a0, a1, a2, a3} {}
        
    Uint256& operator-=(Uint256 const& other) {
        uint8_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            a[i] = sub_borrow(a[i], other.a[i], borrow);
        }
        return *this;
    }
    
    Uint256& operator+=(Uint256 const& other) {
        uint8_t carry = 0;
        for (int i = 0; i < 4; ++i) {
            a[i] = add_carry(a[i], other.a[i], carry);
        }
        return *this;
    }
    
    constexpr Uint256 operator+(Uint256 const& other) const {
        Uint256 result;
        uint8_t carry = 0;
        for (int i = 0; i < 4; ++i) {
            result.a[i] = add_carry(a[i], other.a[i], carry);
        }
        return result;
    }
    
    constexpr Uint256 operator-(Uint256 const& other) const {
        Uint256 result;
        uint8_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            result.a[i] = sub_borrow(a[i], other.a[i], borrow);
        }
        return result;
    }
    
    constexpr bool operator<(Uint256 const& other) const {
        for (int i = 3; i >= 0; --i) {
            if (a[i] == other.a[i]) continue;
            return a[i] < other.a[i];
        }
        return false;
    }

    constexpr bool ith_bit_set(uint32_t i) const {
        return (a[i / 64] >> (i % 64)) & 1;
    }

};

constexpr Uint256 val25519(0xffff'ffff'ffff'ffed, 0xffff'ffff'ffff'ffff, 0xffff'ffff'ffff'ffff, 0x7fff'ffff'ffff'ffff);
constexpr Uint256 val25519_2(0xffff'ffff'ffff'ffeb, 0xffff'ffff'ffff'ffff, 0xffff'ffff'ffff'ffff, 0x7fff'ffff'ffff'ffff);
constexpr Uint256 R2modN(0x5a4);

struct FiniteField25519 {
private:
    Uint256 value;
public:

    FiniteField25519() = default;

    constexpr FiniteField25519(uint64_t a0, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0) :
        value(montMulReduce(Uint256(a0, a1, a2, a3), R2modN)) {}

    FiniteField25519(std::vector<uint8_t> const& bytes) {
        std::memcpy(value.a, bytes.data(), bytes.size());
        value = montMulReduce(value, R2modN);
    }

    FiniteField25519 operator+(FiniteField25519 const& other) const {
        FiniteField25519 result;
        result.value = this->value + other.value;
        if (!(result.value < val25519)) result.value -= val25519;
        return result;
    }

    FiniteField25519 operator-(FiniteField25519 const& other) const {
        FiniteField25519 result;
        result.value = this->value < other.value ? val25519 + this->value - other.value : 
                                                              this->value - other.value;
        return result;
    }
    Uint256 getValue() const {
        return montMulReduce(value, 1);
    }

    static constexpr Uint256 montMulReduce(Uint256 const& a, Uint256 const& b) {
        constexpr Uint256 Np(0x86bca1af286bca1b, 0xbca1af286bca1af2, 0xa1af286bca1af286, 0x2f286bca1af286bc);
        uint64_t T[8]{};
        for (int i = 0; i < 4; ++i) {
            __uint128_t carry = 0;
            for (int j = 0; j < 4; ++j) {
                carry += (__uint128_t)a.a[i] * b.a[j] + T[i + j];
                T[i + j] = carry;
                carry >>= 64;
            }
            T[i + 4] = carry;
        }
        uint64_t m[4]{};
        for (int i = 0; i < 4; ++i) {
            __uint128_t carry = 0;
            for (int j = 0; j < 4; ++j) {
                if (i + j >= 4) break;
                carry += (__uint128_t)T[i] * Np.a[j] + m[i + j];
                m[i + j] = carry;
                carry >>= 64;
            }
        }
        for (int i = 0; i < 4; ++i) {
            __uint128_t carry = 0;
            int j;
            for (j = 0; j < 4; ++j) {
                carry += (__uint128_t)m[i] * val25519.a[j] + T[i + j];
                T[i + j] = carry;
                carry >>= 64;
            }
            do {
                carry += T[i + j];
                T[i + j] = carry;
                carry >>= 64;
                ++j;
            } while (carry);
        }
        Uint256 ret(T[4], T[5], T[6], T[7]);
        return ret < val25519 ? ret : ret - val25519;
    }

    FiniteField25519 operator*(FiniteField25519 const& other) const {
        FiniteField25519 result;
        result.value = montMulReduce(value, other.value);
        return result;
    }

    FiniteField25519 operator/(FiniteField25519 const& other) const {
        auto inv = FiniteField25519::inverse(other);
        return (*this) * inv;
    }

private:
    static FiniteField25519 pow(FiniteField25519 base, Uint256 const& exp) {
        FiniteField25519 result(1);
        for (uint32_t i = 0; i < 256; ++i) {
            if (exp.ith_bit_set(i)) result = result * base;
            base = base * base;
        }
        return result;
    }
    static FiniteField25519 inverse(FiniteField25519 const& value) {
        return FiniteField25519::pow(value, val25519_2);
    }
};
constexpr FiniteField25519 A(486662);



static inline FiniteField25519 square(FiniteField25519 const& x) {
    return x * x;
}

struct AffineFiniteField25519 {
    FiniteField25519 x;
    FiniteField25519 z;
};

static AffineFiniteField25519 doubleX25519(AffineFiniteField25519 const& x) {
    FiniteField25519 sqx = x.x * x.x;
    FiniteField25519 sqz = x.z * x.z;
    FiniteField25519 xz = x.x * x.z;
    return AffineFiniteField25519{
        square(sqx - sqz),
        (sqx + A * xz + sqz) * xz * 4
    };
}

static FiniteField25519 multX25519(FiniteField25519 const& P, std::vector<uint8_t> const& key) {
    AffineFiniteField25519 xi{P, 1};
    AffineFiniteField25519 xi_1 = doubleX25519(xi);
    for (int i = 253; i >= 0; --i) {
        const AffineFiniteField25519 x2i_1{
            square(xi.x * xi_1.x - xi.z * xi_1.z),
            P * square(xi.x * xi_1.z - xi.z * xi_1.x)
        };
        if ((key[i / 8] >> (i % 8)) & 1) {
            xi = x2i_1;
            xi_1 = doubleX25519(xi_1);
        } else {
            xi = doubleX25519(xi);
            xi_1 = x2i_1;
        }
    }
    
    return xi.x / xi.z;
}

std::vector<uint8_t> generatePublicKey(std::vector<uint8_t> privateKey) {
    
    privateKey[0] &= 0xf8;
    privateKey[31] = (privateKey[31] & 0x7f) | 0x40;
    auto mul = multX25519(9, privateKey).getValue();
    std::vector<uint8_t> publicKey(32);
    std::memcpy(publicKey.data(), mul.a, publicKey.size());
    return publicKey;
}
#include <chrono>
using namespace std::chrono;
std::vector<uint8_t> mulKeys(std::vector<uint8_t> privateKey, std::vector<uint8_t> const& otherPublic) {
    privateKey[0] &= 0xf8;
    privateKey[31] = (privateKey[31] & 0x7f) | 0x40;
    FiniteField25519 pub(otherPublic);
    auto mul = multX25519(pub, privateKey).getValue();
    std::vector<uint8_t> result(32);
    std::memcpy(result.data(), mul.a, result.size());
    return result;
}


