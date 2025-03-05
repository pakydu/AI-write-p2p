# toolchain-arm64.cmake

# 设置目标系统和处理器架构
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# 指定交叉编译工具链的路径（根据实际环境修改）
set(TOOLCHAIN_PATH  /opt/linaro-7.5.0/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu)
set(CMAKE_C_COMPILER ${TOOLCHAIN_PATH}/bin/aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PATH}/bin/aarch64-linux-gnu-g++)

# 指定目标系统的根文件系统（如果需要链接动态库）
set(CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_PATH}/sysroot/sysroot-glibc-linaro-2.25-2019.12-aarch64-linux-gnu)

# 调整查找策略
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)  # 查找主机上的程序
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)   # 仅在目标系统中查找库
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)   # 仅在目标系统中查找头文件
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)   # 仅在目标系统中查找包