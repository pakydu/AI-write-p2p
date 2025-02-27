cmake_minimum_required(VERSION 3.10)
#set program name
SET(EXE_NAME stun_client)

#check the os type
MESSAGE(STATUS "OS type is ${CMAKE_SYSTEM}")

#use c++11, enable warning
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++0x -Wall)

#enable debug mode
ADD_DEFINITIONS(-g)

#add the src and head files
AUX_SOURCE_DIRECTORY(. SRC_LIST)

MESSAGE(STATUS, "SRC_LIST: ${SRC_LIST}")
INCLUDE_DIRECTORIES(./)
INCLUDE_DIRECTORIES(../inc)


ADD_EXECUTABLE(${EXE_NAME} ${SRC_LIST})

target_link_libraries(${EXE_NAME} -luv)
