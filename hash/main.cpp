#include <iostream>
#include <string>
#include <openssl/sha.h>

// 生成哈希
std::string generateHash(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];  // 存储哈希结果的数组
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);

    // 将哈希结果转换为十六进制字符串
    std::string hashStr;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", hash[i]);
        hashStr += hex;
    }

    return hashStr;
}

// 校验哈希
bool verifyHash(const std::string& input, const std::string& hash) {
    std::string calculatedHash = generateHash(input);
    return (calculatedHash == hash);
}

int main() {
    std::string input = "Hello, World!";
    std::string hash = generateHash(input);
    std::cout << "Generated Hash: " << hash << std::endl;

    bool isHashValid = verifyHash(input, hash);
    std::cout << "Hash Verification: " << (isHashValid ? "Valid" : "Invalid") << std::endl;

    return 0;
}