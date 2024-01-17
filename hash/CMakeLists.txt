cmake_minimum_required(VERSION 3.10)
project(MyProject)

# 查找 OpenSSL 库并包含头文件
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# 添加可执行文件
add_executable(myapp main.cpp)

# 链接 OpenSSL 库
target_link_libraries(myapp ${OPENSSL_CRYPTO_LIBRARY})