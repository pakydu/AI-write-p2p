cmake_minimum_required(VERSION 3.10)
project(cJSON LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)  # 确保静态库可用于链接共享库

# 同时生成静态库和共享库
add_library(cJSON_static STATIC
    cJSON.c
    cJSON.h
)

add_library(cJSON_shared SHARED
    cJSON.c
    cJSON.h
)

# 设置统一的输出名称（移除后缀）
set_target_properties(cJSON_static PROPERTIES OUTPUT_NAME cJSON)
set_target_properties(cJSON_shared PROPERTIES OUTPUT_NAME cJSON)

set(LIBRARY_OUTPUT_PATH  ${TOP_OUTPUT_DIRECTORY}/lib)

# 公共包含目录
target_include_directories(cJSON_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(cJSON_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of build." FORCE)
endif()
string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_LOWER)
if(BUILD_TYPE_LOWER MATCHES "^(Release|release)$")
        # 共享库：移除所有非必要符号
        add_custom_command(TARGET cJSON_shared POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:cJSON_shared>
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

# 安装规则
install(TARGETS cJSON_static cJSON_shared
    LIBRARY DESTINATION lib   # 共享库
    ARCHIVE DESTINATION lib   # 静态库
    RUNTIME DESTINATION bin   # Windows DLL
)

install(FILES cJSON.h
    DESTINATION include/cjson
)