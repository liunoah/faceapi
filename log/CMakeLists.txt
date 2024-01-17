cmake_minimum_required(VERSION 3.10)
project(SpdlogExample)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)

# 寻找 spdlog 库
find_package(spdlog REQUIRED)

# 添加可执行文件
add_executable(SpdlogExample main.cpp)

# 链接 spdlog 库
target_link_libraries(SpdlogExample PRIVATE spdlog::spdlog)
target_link_libraries(SpdlogExample PRIVATE spdlog::spdlog pthread)