cmake_minimum_required(VERSION 3.10)
project(rt_monitor)


# 设置静态链接优先
set(CMAKE_FIND_LIBRARY_SUFFIXES .a) # 仅查找静态库

# 强制使用静态标准库（GNU 编译器）
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

include_directories(../inc)
aux_source_directory(./ SRC_LIST)

link_directories( ${TOP_OUTPUT_DIRECTORY}/lib)
link_libraries(cJSON)

set(EXECUTABLE_OUTPUT_PATH ${TOP_OUTPUT_DIRECTORY}/bin)

add_executable(rt_monitor ${SRC_LIST})

string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_LOWER)
if(BUILD_TYPE_LOWER MATCHES "^(Release|release)$")
        # 共享库：移除所有非必要符号
        add_custom_command(TARGET rt_monitor POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:rt_monitor>
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