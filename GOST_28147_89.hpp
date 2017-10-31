#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <array>

class GOST_28147_89 {
public:
    enum class Method {
        ECB,
        CBC,
        CFB,
        OFB,
    };

    typedef unsigned char byte_t;
    typedef std::vector<byte_t> vec_byte_t;

    GOST_28147_89(const char* key, const char* iv);
    ~GOST_28147_89() {};

    void encrypt(Method method, std::istream& is, std::ostream& os);
    void decrypt(Method method, std::istream& is, std::ostream& os);

private:  
    std::array<byte_t, 8> _read();
    template<typename T, size_t S>
    T _blockToBits(const std::array<byte_t, S> &block);
    template<size_t S>
    std::string _blockToString(const std::array<byte_t, S> &text_block);
    template<typename T, size_t S>
    std::array<byte_t, S> _bitsToBlock(const T &bits);
 
    uint32_t _f(const std::array<byte_t, 4> &A, const uint32_t &key);
    std::array<byte_t, 8> _block_cipher(const std::array<uint32_t, 8> &__key, const std::array<byte_t, 8> &text_block);
    std::string _encrypt(Method method, const std::array<uint32_t, 8> &__key);

    std::istream* _stream;
    static const std::array<std::array<byte_t, 16>, 8> _s_blocks;
    std::array<uint32_t, 8> _key;
    std::array<byte_t, 8> _initialization_vector;
    bool _decrypting;
};