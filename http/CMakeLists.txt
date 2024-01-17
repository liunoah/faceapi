cmake_minimum_required(VERSION 3.0)
project(MyProject)

# 添加头文件目录
include_directories(/usr/include)

# 添加可执行文件
add_executable(myapp main.cpp)

# 链接 OpenSSL 库
target_link_libraries(myapp crypto)