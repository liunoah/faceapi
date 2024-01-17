cmake_minimum_required(VERSION 3.10)
# 设置C++标准
set(CMAKE_CXX_STANDARD 11)

# 设置项目目标名字
# set(PROJECT_TARGET_NAME testProject)
set(PROJECT_TARGET_NAME testProject)
project(${PROJECT_TARGET_NAME})



# 添加可执行文件
add_executable(${PROJECT_TARGET_NAME} main.cpp token.cpp)

# 查找Crow库
find_package(Crow REQUIRED)
# 寻找 spdlog 库
find_package(spdlog REQUIRED)

# 链接mysqlcppconn库
target_link_libraries(${PROJECT_TARGET_NAME} mysqlcppconn)

# 链接Crow库
target_link_libraries(${PROJECT_TARGET_NAME} Crow::Crow)
# 链接 spdlog 库
target_link_libraries(${PROJECT_TARGET_NAME} spdlog::spdlog)
target_link_libraries(${PROJECT_TARGET_NAME} spdlog::spdlog pthread)

