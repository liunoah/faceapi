cmake_minimum_required(VERSION 3.10)
project(testProject)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)

include_directories(${OPENSSL_INCLUDE_DIR})

# 添加可执行文件
add_executable(testProject api.cpp)