cmake_minimum_required(VERSION 3.10)
project(testProject)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)

# 查找Crow库
find_package(Crow REQUIRED)
# 查找 OpenSSL 库并包含头文件
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# 添加可执行文件
add_executable(testProject test.cpp)

# 链接 OpenSSL 库
target_link_libraries(testProject ${OPENSSL_CRYPTO_LIBRARY})
# 链接Crow库
target_link_libraries(testProject Crow::Crow)