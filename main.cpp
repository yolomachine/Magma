#include "GOST_28147_89.hpp"

int main() {
    GOST_28147_89 ES("to_encrypt.txt");
    ES.encrypt(GOST_28147_89::Method::CBC, std::ofstream("encrypted.txt", std::ios::binary));
    ES.open("encrypted.txt");
    ES.decrypt(GOST_28147_89::Method::CBC, std::ofstream("decrypted.txt", std::ios::binary));
}