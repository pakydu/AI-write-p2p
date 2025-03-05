#ifndef _HANDLE_IP_ROUTE_H_
#define _HANDLE_IP_ROUTE_H_

#include <stdio.h>
#include <stdlib.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>


#define NETLINK_BUFFER_SIZE 4096
#ifndef RTA_FLAGS
#define RTA_FLAGS 14
#endif

// 路由表映射相关
#define MAX_RT_TABLE_ENTRIES 64
#define RT_TABLES_PATH "/etc/iproute2/rt_tables"

//record the interface status which will be used to compare the status changed.
typedef struct if_stat_record {
    char if_name[64];
    int if_index;
    unsigned if_flags;  //we will compare the flage, it it has been changed, we think it should be new event.
    unsigned if_change;
} if_stat_record_st;

typedef struct {
    unsigned int id;
    char name[32];
} rt_table_entry;

// ## 根据上面的数据定义我们的结构体：
typedef struct route_entry {
    // 接口名称，用于存储网络接口的名称
    char name[IF_NAMESIZE];

    // 路由标识符，用于唯一标识一个路由项
    int rt_id;

    // 目的IP地址，表示此路由项的目的网络或主机地址
    char des_ip[64];

    // 网关IP地址，数据包将通过此地址进行转发
    char gw_ip[64];

    // 路由度量值，用于路由选择算法来决定最佳路径
    int metric;

    // IP地址类型，支持AF_INET6（IPv6）和AF_INET（IPv4）
    int ip_type;

    // MAC 链路类型，比如以太网，无线网，移动网等
    int mac_type;
}route_entry_t;

typedef enum {
	METRIC_ETH = 50,
	METRIC_WIFI = 100,
	METRIC_5G = 150,

	// Ending.
	METRIC_MAX = 200
} metric_E;

typedef enum {
	MAC_ETH = 1,
	MAC_WIFI = 2,
	MAC_MOBILE = 3,
} MAC_type_E;


// 函数声明
void handle_link_event(struct nlmsghdr *nlh);
void handle_addr_event(struct nlmsghdr *nlh);
void handle_route_event(struct nlmsghdr *nlh, route_entry_t *rt_items, int rt_len);



void get_rt_table_name(const unsigned int id, char *name);
int init_route_table(route_entry_t *rt_items, int rt_len, int family);
void add_rule_table_priority(int table, int priority);

// 调用示例：添加优先级3、路由表eth1的规则
//add_rule_table_priority(1001, 3);  // 假设 eth1 对应 table ID 1001

//void add_main_rule(int pref, int family);
// 添加 IPv4 规则，优先级1
// add_main_rule(1, AF_INET);
// 添加 IPv6 规则，优先级2
// add_main_rule(2, AF_INET6);
void log_message(int priority, const char *format, ...);

#endif