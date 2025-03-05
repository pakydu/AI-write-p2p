cmake_minimum_required(VERSION 3.10)
project(p2p-client)

set(CMAKE_CXX_STANDARD 17)

#find_package(nlohmann_json 3.9.1 REQUIRED)
#find_package(Catch2 3.9.1 REQUIRED)
include_directories(${PROJECT_SOURCE_DIR}/include)
message(STATUS "${PROJECT_SOURCE_DIR}")

add_compile_options(-Wall -o0 -g)

add_executable(p2p-client
    src/stu_client.cpp
    src/nat_detection.cpp
    src/port_analysis.cpp
)

#target_link_libraries(p2p-client PRIVATE nlohmann_json::nlohmann_json)

#add_executable(nat-test test/nat_test.cpp src/nat_detection.cpp)
#target_link_libraries(nat-test PRIVATE Catch2::Catch2)

## Ubuntu示例 sudo apt install cmake g++ libasio-dev nlohmann-json3-dev