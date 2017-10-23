#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <array>

class GOST_28147_89 {
public:
    enum class Method {
        ECB,
        XOR,
        CFB,
        MAC,
    };

    typedef unsigned char byte_t;
    typedef std::vector<byte_t> vec_byte_t;

    GOST_28147_89() {};
    GOST_28147_89(const char* file);
    ~GOST_28147_89() {};

    template<typename T>
    void open(T file);

    template<typename T>
    void encrypt(Method method, T& os);
    template<typename T>
    void decrypt(Method method, T& os);

private:  
    std::array<byte_t, 8> _read();
    
    std::string _encrypt(Method method, const std::array<uint32_t, 8> &__key);

    uint32_t _f(const std::array<byte_t, 4> &A, const uint32_t &key);
    std::string _ECB(const std::array<uint32_t, 8> &__key);
    std::string _XOR(const std::array<uint32_t, 8> &__key);
    std::string _CFB(const std::array<uint32_t, 8> &__key);

    std::ifstream _file;
    static const std::array<std::array<byte_t, 16>, 8> _s_blocks;
    static const std::array<uint32_t, 8> _key;
};