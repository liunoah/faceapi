// token.cpp
// token.cpp

#include "token.h" // 包含头文件
#include <string>
#include <unordered_set>
#include <iostream>
#include <random>
#include <string>

// 存储有效的Token
std::unordered_set<std::string> validTokens;
// 存储失效的Token
std::unordered_set<std::string> invalidTokens;

// 生成Token
std::string generateToken() {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int length = 32;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.size() - 1);
    
    std::string token;
    
    for (int i = 0; i < length; ++i) {
        token += charset[dis(gen)];
    }
    validTokens.insert(token);
    return token;
}

// 验证Token
bool validateToken(const std::string& token) {
    std::cout << "invalidTokens: " << invalidTokens.count(token) << std::endl;
    std::cout << "validTokens: " << validTokens.count(token) << std::endl;
    // 检查Token是否在失效Token集合中
    if (invalidTokens.count(token) > 0) {
        return false;
    }

    // 检查Token是否在有效Token集合中
    return validTokens.count(token) > 0;
}

// 使Token失效
void invalidateToken(const std::string& token) {
    // 将Token从有效Token集合中移除，并添加到失效Token集合中
    validTokens.erase(token);
    invalidTokens.insert(token);
}