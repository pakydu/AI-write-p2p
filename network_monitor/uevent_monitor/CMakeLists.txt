cmake_minimum_required(VERSION 3.10)
project(uevent_monitor)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

# 包含目录
include_directories(${CMAKE_SOURCE_DIR})


# 源文件
set(SOURCES
    uevent_monitor.c
)

set(EXECUTABLE_OUTPUT_PATH ${TOP_OUTPUT_DIRECTORY}/bin)

# 可执行文件
add_executable(uevent_monitor ${SOURCES})

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of build." FORCE)
endif()
string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_LOWER)
if(BUILD_TYPE_LOWER MATCHES "^(Release|release)$")
        # 共享库：移除所有非必要符号
        add_custom_command(TARGET uevent_monitor POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:uevent_monitor>
            COMMENT "Stripping symbols from shared library (Release mode)"
        )

        # 静态库：默认保留符号，如需移除调试符号可取消注释
        # add_custom_command(TARGET cJSON_static POST_BUILD
        #     COMMAND ${CMAKE_STRIP} --strip-debug $<TARGET_FILE:cJSON_static>
        #     COMMENT "Stripping debug symbols from static library"
        # )
else()
        message(STATUS "Skipping strip for ${CMAKE_BUILD_TYPE} build type")
endif()