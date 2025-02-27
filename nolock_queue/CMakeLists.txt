# #set program name
# SET(EXE_NAME stun_server)

# #check the os type
# MESSAGE(STATUS "OS type is ${CMAKE_SYSTEM}")

# #use c++11, enable warning
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
# # SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++0x -Wall)

# #enable debug mode
# ADD_DEFINITIONS(-g)

# #add the src and head files
# AUX_SOURCE_DIRECTORY(. SRC_LIST)

# MESSAGE(STATUS, "SRC_LIST: ${SRC_LIST}")
# INCLUDE_DIRECTORIES(./)
# INCLUDE_DIRECTORIES(../inc)


# ADD_EXECUTABLE(${EXE_NAME} ${SRC_LIST})

# target_link_libraries(${EXE_NAME} -luv)

cmake_minimum_required(VERSION 3.10)

project(
	nolock
	VERSION 1.0.0
	LANGUAGES CXX
)

SET(EXE_NAME nolock)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
# 设置 C++11
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 添加警告
add_compile_options(-Wall -Wextra -Wpedantic)
ADD_DEFINITIONS(-g)

# 链接 pthread
find_package(Threads REQUIRED)

aux_source_directory(. SRC_LIST)
file(GLOB_RECURSE  HEAD_LIST ./*.h)
message(${SRC_LIST})
#link_libraries(pthread)
add_executable( ${EXE_NAME} ${SRC_LIST} )
# set_target_properties(${EXE_NAME} PROPERTIES 
#     RELEASE_POST_PROCESS_COMMAND "strip --strip-unneeded $<TARGET_FILE:${EXE_NAME}>"
# )
string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_LOWER)
if(BUILD_TYPE_LOWER MATCHES "^(Release|release)$")
add_custom_command(TARGET ${EXE_NAME} POST_BUILD
    COMMAND strip --strip-unneeded $<TARGET_FILE:${EXE_NAME}>
    COMMENT "Stripping symbols from ${EXE_NAME}"
)
else()
	message(STATUS "Skipping strip for build type ${CMAKE_BUILD_TYPE}")
endif()
#target_link_libraries( ${PROJECT_NAME} -luv )
# 链接库
target_link_libraries(${EXE_NAME} PRIVATE Threads::Threads)


