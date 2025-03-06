#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
//#include <linux/uevent.h>
#include <errno.h>

#define UEVENT_BUFFER_SIZE 2048

/**
 * @brief 监听uevent事件的主函数
 * 
 * 该函数创建并绑定一个netlink套接字，用于监听内核发送的uevent事件。
 * 当接收到事件时，会打印出事件的详细信息。
 */
void monitor_uevents() {
    int sock_fd;
    struct sockaddr_nl sa;
    char buffer[UEVENT_BUFFER_SIZE];
    // struct nlmsghdr *nlh;
    int len;

    // 创建 netlink 套接字
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (sock_fd < 0) {
        perror("socket");
        return;
    }

    // 初始化 netlink 地址结构
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = getpid();
    sa.nl_groups = 1; // 监听内核广播的uevent事件

    // 绑定套接字
    if (bind(sock_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(sock_fd);
        return;
    }

    // 消息处理循环
    while (1) {
        len = recv(sock_fd, buffer, sizeof(buffer), 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }

        // 解析uevent消息
		
        char *pos = buffer;
		printf("\n[UEVENT]:%s\n", pos);
		pos += strlen(pos) + 1;
        while (pos < buffer + len) {
            printf("\t[INFO]: %s\n", pos);
            pos += strlen(pos) + 1;
			printf("\t-------------------------------\n");
        }
    }

    close(sock_fd);
}

/**
 * @brief 程序入口函数
 * 
 * @param argc 命令行参数个数
 * @param argv 命令行参数数组
 * @return int 程序退出码
 * 
 * 该函数启动uevent事件的监听。
 */
int main(void) {
    monitor_uevents();
    return 0;
}