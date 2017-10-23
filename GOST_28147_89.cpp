#include "GOST_28147_89.hpp"

//  id-GostR3411-94-TestParamSet+DiagCornerSwap
const std::array<std::array<GOST_28147_89::byte_t, 16>, 8> GOST_28147_89::_s_blocks = {
    0xC, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x1,
    0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9,
    0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB,
    0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3,
    0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2,
    0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE,
    0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC,
    0x3, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0x4,
};

const std::array<uint32_t, 8> GOST_28147_89::_key = {
    0xACEF,
    0xBACE,
    0xDBAC,
    0xFDBA,

    0x0123,
    0x4567,
    0x89AB,
    0xCDEF,
};

void operator >> (std::basic_istream<char, std::char_traits<char>> &is, GOST_28147_89::vec_byte_t& v) {
    GOST_28147_89::byte_t b;
    is >> b;
    v.push_back(b);
};

GOST_28147_89::GOST_28147_89(const char* filename) {
    open(filename);
};

template<typename T>
void GOST_28147_89::open(T filename) {
    if (_file.is_open())
        _file.close();
    _file.open(filename, std::ios::binary);
    _file.peek();
};
template void GOST_28147_89::open<const char*>(const char*);
template void GOST_28147_89::open<std::string&>(std::string&);

template<typename T>
void GOST_28147_89::encrypt(Method method, T& os) {
    std::string s = _encrypt(method, _key);
    for (size_t i = 0; i < s.length(); ++i)
        os << s[i];
};
template void GOST_28147_89::encrypt<std::ostream>(Method, std::ostream&);
template void GOST_28147_89::encrypt<std::ofstream>(Method, std::ofstream&);

template<typename T>
void GOST_28147_89::decrypt(Method method, T& os) {
    std::array<uint32_t, 8> reversed_key = {
        _key[7],
        _key[6],
        _key[5],
        _key[4],
        _key[3],
        _key[2],
        _key[1],
        _key[0],
    };
    os << _encrypt(method, reversed_key).c_str();
};
template void GOST_28147_89::decrypt<std::ostream>(Method, std::ostream&);
template void GOST_28147_89::decrypt<std::ofstream>(Method, std::ofstream&);

std::string GOST_28147_89::_encrypt(Method method, const std::array<uint32_t, 8> &__key) {
    std::string cipher_text;
    switch (method) {
    case Method::ECB:
        cipher_text = _ECB(__key);
    default:
        break;
    }
    return cipher_text;
};

std::array<GOST_28147_89::byte_t, 8> GOST_28147_89::_read() {
    vec_byte_t v;
    while (!_file.eof() && v.size() < 8) {
        _file >> std::noskipws >> v;
        _file.peek();
    }
    while (v.size() < 8)
        v.push_back(0);
    return std::array<byte_t, 8> {
        v[0],
        v[1],
        v[2],
        v[3],
        v[4],
        v[5],
        v[6],
        v[7],
    };
}

uint32_t GOST_28147_89::_f(const std::array<byte_t, 4> &A, const uint32_t &key) {
    std::array<byte_t, 8> four_bit_blocks;
    uint64_t A_bits = 0;
    for (size_t i = 0; i < A.size(); ++i)
        A_bits |= static_cast<uint32_t>(A[i]) << (A.size() - i - 1) * 8;

    A_bits = (A_bits + key) % (1ull << 32);
    four_bit_blocks[7] = _s_blocks.at(0).at((A_bits & 0xF));
    four_bit_blocks[6] = _s_blocks.at(1).at((A_bits & 0xF0) >> 4);
    four_bit_blocks[5] = _s_blocks.at(2).at((A_bits & 0xF00) >> 8);
    four_bit_blocks[4] = _s_blocks.at(3).at((A_bits & 0xF000) >> 12);
    four_bit_blocks[3] = _s_blocks.at(4).at((A_bits & 0xF0000) >> 16);
    four_bit_blocks[2] = _s_blocks.at(5).at((A_bits & 0xF00000) >> 20);
    four_bit_blocks[1] = _s_blocks.at(6).at((A_bits & 0xF000000) >> 24);
    four_bit_blocks[0] = _s_blocks.at(7).at((A_bits & 0xF0000000) >> 28);
    
    uint32_t res = 0;
    for (size_t i = 0; i < four_bit_blocks.size(); ++i)
        res |= static_cast<uint32_t>(four_bit_blocks[i]) << (four_bit_blocks.size() - i - 1) * 4;

    return ((res << 11) | (res >> 21));
};

std::string GOST_28147_89::_ECB(const std::array<uint32_t, 8> &__key) {
    std::string output;
    while (!_file.eof()) {
        std::array<byte_t, 8> text_block = _read();
        std::array<byte_t, 4> B = {
            text_block[0],
            text_block[1],
            text_block[2],
            text_block[3],
        };
        std::array<byte_t, 4> A = {
            text_block[4],
            text_block[5],
            text_block[6],
            text_block[7],
        };
        for (size_t i = 0; i < 32; ++i) {
            uint32_t key;
            if (_key == __key)
                key = __key.at(i < 24 ? i % 8 : 31 - i);
            else
                key = __key.at(i < 8 ? 7 - i : i % 8);
            uint32_t B_bits = 0;
            for (size_t j = 0; j < B.size(); ++j)
                B_bits |= static_cast<uint32_t>(B[j]) << (B.size() - j - 1) * 8;
            B_bits ^= _f(A, key);
            B = A;
            A = {
                (B_bits >> 24) & 0xFF,
                (B_bits >> 16) & 0xFF,
                (B_bits >> 8) & 0xFF,
                B_bits & 0xFF,
            };
        }
        output += A[0];
        output += A[1];
        output += A[2];
        output += A[3];
        output += B[0];
        output += B[1];
        output += B[2];
        output += B[3];
    }
    return output;
};