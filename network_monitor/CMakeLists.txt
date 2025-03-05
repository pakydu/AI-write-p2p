cmake_minimum_required(VERSION 3.10)
project(RootProject)

# 设置输出目录
set(TOP_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})


# 设置子目录
add_subdirectory(cJson)
add_subdirectory(rt_monitor)


# 可选：设置交叉编译工具链（如果需要）
# set(CMAKE_TOOLCHAIN_FILE toolchain-arm64.cmake)