cmake_minimum_required(VERSION 3.10)
project(testProject)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)

# 添加可执行文件
add_executable(testProject test.cpp)

# 链接mysqlcppconn库
target_link_libraries(testProject mysqlcppconn)
