#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/route.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/fib_rules.h>
#include <stdarg.h>
#include "handle_ip_route.h"

#ifdef NDEBUG
#include <syslog.h>
#endif

extern int g_log_level;


/*
路由条目关键字段解析
broadcast 192.168.32.0 dev br-lan table local proto kernel scope link src 192.168.32.1
字段	       对应 Netlink 属性或结构体字段	       说明
broadcast	   rtm_type（类型为 RTN_BROADCAST）	     表示路由类型是广播路由。
192.168.32.0	RTA_DST（目的地址）						目标地址（此处是广播地址）。
dev br-lan		RTA_OIF（输出接口索引）					通过 if_indextoname 转换接口索引为名称（如 br-lan）。
table local		RTA_TABLE（路由表 ID）					路由表 ID（local 对应 255），需解析为名称（如 get_rt_table_name）。
proto kernel	rtm_protocol（协议类型）				协议类型为 RTPROT_KERNEL（内核自动生成）。
scope link		rtm_scope（作用域）					作用域为 RT_SCOPE_LINK（链路本地）。
src 192.168.32.1	RTA_PREFSRC（首选源地址）		路由优先使用的源 IP 地址。

代码实现示例
root@localhost:/home/android# ip route show table 0
default via 10.180.146.254 dev eth0 table eth0 proto static
10.180.146.0/24 dev eth0 table eth0 proto static scope link
172.17.0.0/16 dev docker0 table eth0 scope link linkdown
10.180.146.0/24 dev eth0 table eth0_local proto static scope link
default dev dummy0 table dummy0 proto static scope link
10.180.146.0/24 dev eth0 proto kernel scope link src 10.180.146.38
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
192.168.32.0/24 dev br-lan proto kernel scope link src 192.168.32.1
broadcast 10.180.146.0 dev eth0 table local proto kernel scope link src 10.180.146.38
local 10.180.146.38 dev eth0 table local proto kernel scope host src 10.180.146.38
broadcast 10.180.146.255 dev eth0 table local proto kernel scope link src 10.180.146.38
broadcast 127.0.0.0 dev lo table local proto kernel scope link src 127.0.0.1
local 127.0.0.0/8 dev lo table local proto kernel scope host src 127.0.0.1
local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1
broadcast 127.255.255.255 dev lo table local proto kernel scope link src 127.0.0.1
broadcast 172.17.0.0 dev docker0 table local proto kernel scope link src 172.17.0.1 linkdown
local 172.17.0.1 dev docker0 table local proto kernel scope host src 172.17.0.1
broadcast 172.17.255.255 dev docker0 table local proto kernel scope link src 172.17.0.1 linkdown
broadcast 192.168.32.0 dev br-lan table local proto kernel scope link src 192.168.32.1
local 192.168.32.1 dev br-lan table local proto kernel scope host src 192.168.32.1
broadcast 192.168.32.255 dev br-lan table local proto kernel scope link src 192.168.32.1
2040::/64 dev eth0 table eth0 proto kernel metric 256 expires 2591947sec pref medium
2040::/64 dev eth0 table eth0 proto static metric 1024 pref medium
fe80::/64 dev eth0 table eth0 proto kernel metric 256 pref medium
fe80::/64 dev eth0 table eth0 proto static metric 1024 pref medium
default via fe80::631:10ff:feb2:da64 dev eth0 table eth0 proto ra metric 1024 expires 1747sec hoplimit 64 pref medium
fe80::/64 dev br-lan table 1038 proto kernel metric 256 pref medium
2040::/64 dev eth0 table eth0_local proto static metric 1024 pref medium
fe80::/64 dev eth0 table eth0_local proto static metric 1024 pref medium
fe80::/64 dev dummy0 table dummy0 proto kernel metric 256 pref medium
default dev dummy0 table dummy0 proto static metric 1024 pref medium
fe80::/64 dev sipa_dummy0 proto kernel metric 256 pref medium
local ::1 dev lo table local proto kernel metric 0 pref medium
local 2040::4547:a9f0:dfb:921e dev eth0 table local proto kernel metric 0 pref medium
local 2040::9efb:e4a:869e:9fe0 dev eth0 table local proto kernel metric 0 pref medium
local fe80::88f:4fff:fedd:10da dev sipa_dummy0 table local proto kernel metric 0 pref medium
local fe80::38ee:fb2c:e073:1732 dev eth0 table local proto kernel metric 0 pref medium
local fe80::5091:feff:fed9:175 dev dummy0 table local proto kernel metric 0 pref medium
local fe80::a076:44ff:fed7:3089 dev br-lan table local proto kernel metric 0 pref medium
multicast ff00::/8 dev sipa_dummy0 table local proto kernel metric 256 pref medium
multicast ff00::/8 dev dummy0 table local proto kernel metric 256 pref medium
multicast ff00::/8 dev eth0 table local proto kernel metric 256 pref medium
multicast ff00::/8 dev br-lan table local proto kernel metric 256 pref medium
root@localhost:/home/android#
*/

static int update_rt_main(const route_entry_t *item, route_entry_t *items, int index);
static void add_attr(struct nlmsghdr *nh, size_t maxlen, int type, const void *data, size_t datalen);
static void send_netlink_request(struct nlmsghdr *nh);
static void parse_attributes(struct rtattr *attrs[], int max, struct rtattr *rta, int len);
static void print_ip(int family, void *addr);

/**
 * @brief 初始化路由表映射
 * 
 * @param rt_table_map 路由表映射数组
 * @param rt_table_count 路由表数量指针
 * 
 * 该函数从系统路由表文件/proc/net/route中读取路由表信息，并填充到rt_table_map数组中。
 */
static void init_rt_table_map(rt_table_entry *rt_table_map, int *rt_table_count) {
    FILE *fp = fopen(RT_TABLES_PATH, "r");
    if (!fp) {
        perror("Failed to open " RT_TABLES_PATH);
        return;
    }

    char line[128];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        unsigned int id;
        char name[32];
        if (sscanf(line, "%u %31s", &id, name) == 2) {
            if (*rt_table_count < MAX_RT_TABLE_ENTRIES) {
                rt_table_map[*rt_table_count].id = id;
                strncpy(rt_table_map[*rt_table_count].name, name, sizeof(rt_table_map[0].name));
                *rt_table_count++;
            }
        }
    }

    fclose(fp);
}


//--- 通用工具函数 ---
/**
 * @brief 解析路由属性
 * 
 * @param attrs 属性数组，用于存储解析后的属性
 * @param max 最大属性类型
 * @param rta 指向路由属性的指针
 * @param len 路由属性的长度
 * 
 * 该函数遍历路由属性链表，将属性类型小于等于max的属性存入attrs数组中。
 */
static void parse_attributes(struct rtattr *attrs[], int max, struct rtattr *rta, int len) {
    memset(attrs, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            attrs[rta->rta_type] = rta;
        }
        rta = RTA_NEXT(rta, len);
    }
}



/**
 * @brief 打印IP地址
 * 
 * @param family 地址族（AF_INET或AF_INET6）
 * @param addr 指向IP地址的指针
 * 
 * 该函数将IP地址转换为字符串格式并打印。
 */
static void print_ip(int family, void *addr) {
    char ip_str[INET6_ADDRSTRLEN];
    const char *ret = inet_ntop(family, addr, ip_str, sizeof(ip_str));
    if (ret) {
        log_message(LOG_NOTICE,"%s", ret);
    } else {
        log_message(LOG_NOTICE,"invalid");
    }
}



/**
 * @brief 添加Netlink属性
 * 
 * @param nh Netlink消息头指针
 * @param maxlen 消息的最大长度
 * @param type 属性类型
 * @param data 指向属性数据的指针
 * @param datalen 属性数据的长度
 * 
 * 该函数向Netlink消息中添加一个属性。
 */
static void add_attr(struct nlmsghdr *nh, size_t maxlen, int type, const void *data, size_t datalen) {
    struct rtattr *rta;
    size_t len = RTA_LENGTH(datalen);
    
    rta = (struct rtattr*)(((char*)nh) + NLMSG_ALIGN(nh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, datalen);
    nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + len;
}

/**
 * @brief 发送Netlink请求
 * 
 * @param nh Netlink消息头指针
 * 
 * 该函数通过Netlink套接字发送请求消息。
 */
static void send_netlink_request(struct nlmsghdr *nh) {
    struct sockaddr_nl sa;
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    
    nh->nlmsg_seq = 1;
    nh->nlmsg_pid = getpid();
    
    sendto(fd, nh, nh->nlmsg_len, 0, (struct sockaddr*)&sa, sizeof(sa));
    close(fd);
}

/**
 * @brief 获取路由表名称
 * 
 * @param id 路由表ID
 * @param name 用于存储路由表名称的缓冲区
 * 
 * 该函数根据路由表ID获取对应的路由表名称。如果ID不在预定义的范围内，则返回"unknow"。
 */
void get_rt_table_name(const unsigned int id, char *name) {
	rt_table_entry rt_table_map[MAX_RT_TABLE_ENTRIES];
	int rt_table_count = 0;
	init_rt_table_map(rt_table_map, &rt_table_count);
    for (int i = 0; i < rt_table_count; i++) {
        if (rt_table_map[i].id == id) {
            strcpy(name,rt_table_map[i].name);
			return;
        }
    }

    switch (id) {
        case 255: strcpy(name,"local"); break;
        case 254: strcpy(name,"main"); break;
        case 253: strcpy(name,"default");break;
        case 0:   strcpy(name,"unspec"); break;
        default:  strcpy(name,"unknow"); break;;
    }
	return;
}


//--- 链路事件处理 ---
/**
 * @brief 处理链路事件
 * 
 * @param nlh netlink消息头指针
 * 
 * 该函数处理网络接口创建或删除事件，记录接口名称、状态和MAC地址等信息。
 */
void handle_link_event(struct nlmsghdr *nlh) {
    struct ifinfomsg *ifi = NLMSG_DATA(nlh);
    struct rtattr *attrs[IFLA_MAX+1];
    char ifname[IF_NAMESIZE] = "unknow";

    parse_attributes(attrs, IFLA_MAX, IFLA_RTA(ifi), NLMSG_PAYLOAD(nlh, sizeof(*ifi)));

    const char *action = (nlh->nlmsg_type == RTM_NEWLINK) ? "created" : "removed";
    log_message(LOG_INFO,"\n[LINK] %s: %s (index %d)\n", 
          action,
          if_indextoname(ifi->ifi_index, ifname) ? ifname : "unknown",
          ifi->ifi_index);
	if (attrs[IFLA_IFNAME]) {
        log_message(LOG_INFO,"\tName: %s\n", (char *)RTA_DATA(attrs[IFLA_IFNAME]));
    }
    char *action2 = (ifi->ifi_flags & IFF_RUNNING) ? "up-running" : "down or not running";
    log_message(LOG_INFO,"  %s link %s\n", ifname, action2);

    if (attrs[IFLA_ADDRESS]) {
        unsigned char *mac = RTA_DATA(attrs[IFLA_ADDRESS]);
        log_message(LOG_INFO,"\tMAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

//--- IP地址事件处理 ---
/**
 * @brief 处理IP地址事件
 * 
 * @param nlh netlink消息头指针
 * 
 * 该函数处理IP地址添加或删除事件，记录IP地址、广播地址和多播地址等信息。
 */
void handle_addr_event(struct nlmsghdr *nlh) {
    struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
    struct rtattr *attrs[IFA_MAX+1];
    
    parse_attributes(attrs, IFA_MAX, IFA_RTA(ifa), NLMSG_PAYLOAD(nlh, sizeof(*ifa)));
    
    const char *action = (nlh->nlmsg_type == RTM_NEWADDR) ? "added" : "removed";
    log_message(LOG_INFO,"\n[ADDR] %s: ", action);

    if (attrs[IFA_LOCAL]) {
        print_ip(ifa->ifa_family, RTA_DATA(attrs[IFA_LOCAL]));
    } else if (attrs[IFA_ADDRESS]) {
        print_ip(ifa->ifa_family, RTA_DATA(attrs[IFA_ADDRESS]));
    }
    log_message(LOG_INFO,"/%d\n", ifa->ifa_prefixlen);

    if (attrs[IFA_BROADCAST]) {
        log_message(LOG_INFO,"\tBroadcast: ");
        print_ip(ifa->ifa_family, RTA_DATA(attrs[IFA_BROADCAST]));
        log_message(LOG_INFO,"\n");
    }

	if (attrs[IFA_MULTICAST]) {
        log_message(LOG_INFO,"\tMulticast: ");
        print_ip(ifa->ifa_family, RTA_DATA(attrs[IFA_MULTICAST]));
        log_message(LOG_INFO,"\n");
    }

    if (attrs[IFA_LABEL]) {
        log_message(LOG_INFO,"\tLabel: %s\n", (char *)RTA_DATA(attrs[IFA_LABEL]));
    }
}

//--- 路由事件处理 ---
/**
 * @brief 处理路由事件
 * 
 * @param nlh netlink消息头指针
 * @param rt_items 路由条目数组
 * @param rt_len 路由条目数量
 * 
 * 该函数处理路由添加或删除事件，记录路由类型、目的地址、网关、接口等信息，
 * 并在必要时更新主路由表。
 */
void handle_route_event(struct nlmsghdr *nlh, route_entry_t *rt_items, int rt_len) {
    struct rtmsg *rt = NLMSG_DATA(nlh);
    struct rtattr *attrs[RTA_MAX+1];

	char ifname[IF_NAMESIZE] = {0};
	char dst[INET6_ADDRSTRLEN] = {0};
	char src[INET6_ADDRSTRLEN] = {0};
	char gateway[INET6_ADDRSTRLEN] = {0};
	char mask[INET6_ADDRSTRLEN] = {0};
    
    parse_attributes(attrs, RTA_MAX, RTM_RTA(rt), NLMSG_PAYLOAD(nlh, sizeof(*rt)));
    
    const char *action = (nlh->nlmsg_type == RTM_NEWROUTE) ? "added" : "removed";
    
	int family = rt->rtm_family;
	const char *route_type = "other";
	int ifindex = 0;
	uint32_t priority = 0;
	uint32_t table_id = 0;
	const char *proto_name = "unknown";
	const char *scope_name = "unknown";

    if (attrs[RTA_DST]) {
		inet_ntop(rt->rtm_family, RTA_DATA(attrs[RTA_DST]), 
									dst, sizeof(dst));
		
		switch (rt->rtm_type) {
    		case RTN_UNICAST:    route_type = "unicast"; break;
            case RTN_LOCAL:      route_type = "local"; break;
            case RTN_BROADCAST:  route_type = "broadcast"; break;
            case RTN_MULTICAST:  route_type = "multicast"; break;
            case RTN_ANYCAST:    route_type = "anycast"; break;
            case RTN_BLACKHOLE:  route_type = "blackhole"; break;
            case RTN_UNREACHABLE:route_type = "unreachable"; break;
            case RTN_PROHIBIT:   route_type = "prohibit"; break;
            case RTN_THROW:      route_type = "throw"; break;
            case RTN_NAT:        route_type = "nat"; break;
            case RTN_XRESOLVE:   route_type = "xresolve"; break;
            default:             route_type = "unknown"; break;
		}
    }
    if (attrs[RTA_GATEWAY]) {
		inet_ntop(rt->rtm_family, RTA_DATA(attrs[RTA_GATEWAY]), gateway, sizeof(gateway));
    }
    if (attrs[RTA_OIF]) {
        ifindex = *(int *)RTA_DATA(attrs[RTA_OIF]);
        strcpy(ifname, if_indextoname(ifindex, ifname) ? ifname : "unknown");
    }

	// 其他常见属性处理示例
	if (attrs[RTA_SRC]) {
		inet_ntop(rt->rtm_family, RTA_DATA(attrs[RTA_SRC]), src, sizeof(src));
	}

	if (attrs[RTA_PRIORITY]) {
		priority = *(uint32_t *)RTA_DATA(attrs[RTA_PRIORITY]);
	}

	if (attrs[RTA_TABLE]) {
		table_id = *(uint32_t *)RTA_DATA(attrs[RTA_TABLE]);
	}

	// 协议类型（如 kernel、static）
	switch (rt->rtm_protocol) {
		case RTPROT_UNSPEC:   proto_name = "unspec";   break;  // 0
		case RTPROT_REDIRECT: proto_name = "redirect"; break;  // 1
		case RTPROT_KERNEL:   proto_name = "kernel";   break;  // 2
		case RTPROT_BOOT:     proto_name = "boot";     break;  // 3
		case RTPROT_STATIC:   proto_name = "static";   break;  // 4
		case RTPROT_RA:       proto_name = "ra";       break;  // 9  (IPv6路由通告)
		case RTPROT_DHCP:     proto_name = "dhcp";     break;  // 16 
		case RTPROT_ZEBRA:    proto_name = "zebra";    break;  // 11 (路由守护进程)
		case RTPROT_BABEL:    proto_name = "babel";    break;  // 42 (Babel协议)
		//case RTPROT_BGP:      proto_name = "bgp";      break;  // 186
		//case RTPROT_OSPF:     proto_name = "ospf";     break;  // 188
		//case RTPROT_RIP:      proto_name = "rip";      break;  // 189
		//case RTPROT_EIGRP:    proto_name = "eigrp";    break;  // 192
		default:
			if (rt->rtm_protocol >= RTPROT_STATIC && rt->rtm_protocol < 250) {
				proto_name = "dynamic";  // 用户态协议动态分配范围
			} else {
				proto_name = "reserved";
			}
			break;
	}

	// 作用域（如 link、host）
	switch (rt->rtm_scope) {
		case RT_SCOPE_UNIVERSE:  scope_name = "global"; break; //0,全局有效（默认值），适用于大多数路由。
        case RT_SCOPE_SITE:      scope_name = "site";   break; //150,站点本地
        case RT_SCOPE_LINK:      scope_name = "link";   break; //253
        case RT_SCOPE_HOST:      scope_name = "host";   break; //254
        case RT_SCOPE_NOWHERE:   scope_name = "nowhere";break; //255
        default:
            scope_name = "unknown";
            break;
	}

	// 首选源地址
	// if (attrs[RTA_PREFSRC]) {
	// 	printf("  Preferred Source: ");
	// 	print_ip(rt->rtm_family, RTA_DATA(attrs[RTA_PREFSRC]));
	// 	printf("\n");
	// }

#if 0
	if (attrs[RTA_METRICS]) {
		struct rtattr *metrics_attr = attrs[RTA_METRICS];
		int remaining_len = RTA_PAYLOAD(metrics_attr);  // 获取嵌套属性的有效载荷长度
		struct rtattr *sub_attr;

		// 遍历嵌套属性
		for (sub_attr = RTA_DATA(metrics_attr); 
			RTA_OK(sub_attr, remaining_len); 
			sub_attr = RTA_NEXT(sub_attr, remaining_len)) {

			switch (sub_attr->rta_type) {
				case RTAX_MTU:  // MTU
					if (RTA_PAYLOAD(sub_attr) >= sizeof(uint32_t)) {
						uint32_t mtu = *(uint32_t *)RTA_DATA(sub_attr);
						printf("  MTU: %u\n", mtu);
					}
					break;

				case RTAX_WINDOW:  // TCP窗口大小
					if (RTA_PAYLOAD(sub_attr) >= sizeof(uint32_t)) {
						uint32_t window = *(uint32_t *)RTA_DATA(sub_attr);
						printf("  Window: %u\n", window);
					}
					break;

				case RTAX_RTT:  // 往返时间（RTT）
					if (RTA_PAYLOAD(sub_attr) >= sizeof(uint32_t)) {
						uint32_t rtt = *(uint32_t *)RTA_DATA(sub_attr);
						printf("  RTT: %u ms\n", rtt);
					}
					break;

				case RTAX_HOPLIMIT:  // 跳数限制（IPv6）
					if (RTA_PAYLOAD(sub_attr) >= sizeof(int)) {
						int hoplimit = *(int *)RTA_DATA(sub_attr);
						printf("  Hoplimit: %d\n", hoplimit);
					}
					break;

				// 其他支持的属性类型
				case RTAX_FEATURES:
				case RTAX_INITCWND:
				case RTAX_QUICKACK:
					// 根据需要添加处理逻辑
					break;

				default:
					printf("  Unknown metric type: %d (len=%d)\n", 
						sub_attr->rta_type, sub_attr->rta_len);
					break;
			}
		}
	}

	if (attrs[RTA_FLAGS]) {
		uint32_t flags = *(uint32_t *)RTA_DATA(attrs[RTA_FLAGS]);
		printf("  Flags: 0x%x\n", flags);
	}
#endif

	//debug:
	log_message(LOG_INFO,"\n[ROUTE] %s for %s:\n", action, ifname);
	log_message(LOG_INFO,"\tFamily: %s\n", (rt->rtm_family == AF_INET) ? "IPv4" : "IPv6");
	log_message(LOG_INFO,"\tDestination: %s\n", dst[0] ? dst : "0.0.0.0");
	log_message(LOG_INFO,"\tRoute_type: %s\n", route_type);
	log_message(LOG_INFO,"\tSrc: %s\n", src);
	//log_message(LOG_INFO,"\tPri: %d\n", metric);
	log_message(LOG_INFO,"\tTable_id: %d\n", table_id);
	log_message(LOG_INFO,"\tNetmask: %s\n", mask);
	log_message(LOG_INFO,"\tGateway: %s\n", gateway[0] ? gateway : "0.0.0.0");
	log_message(LOG_INFO,"\tInterface Index: %d (%s)\n\n", ifindex, ifname);
				

	//update the rt_entry：
	if (strcmp(action, "added") == 0) {
		for (int i = 0; i < rt_len; i++) {
			if (strcmp(rt_items[i].name, ifname) == 0 && rt_items[i].ip_type == rt->rtm_family) {
				route_entry_t item = {0};
				strcpy(item.name, ifname);
				item.rt_id = table_id;
				item.ip_type = rt->rtm_family;
				strcpy(item.des_ip, dst[0] ? dst : "0.0.0.0");
				strcpy(item.gw_ip, gateway[0] ? gateway : "0.0.0.0");
				//item.metric = metric;
				update_rt_main(&item, rt_items, i);
			}
		}
	}
}

/**
 * @brief 添加路由规则优先级
 * 
 * @param table 路由表ID
 * @param priority 优先级
 * 
 * 该函数通过netlink消息向内核添加指定路由表的优先级规则。
 */
void add_rule_table_priority(int table, int priority) {
    struct {
        struct nlmsghdr nh;
        struct rtmsg rt;
        char buf[256];
    } req;

    // 初始化 netlink 消息头
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nh.nlmsg_type = RTM_NEWRULE;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;

    // 配置路由规则
    req.rt.rtm_family = AF_INET;  // 或 AF_INET6
    req.rt.rtm_table = RT_TABLE_UNSPEC;
    req.rt.rtm_type = RTN_UNICAST;
    req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
    req.rt.rtm_protocol = RTPROT_BOOT;
    req.rt.rtm_flags = 0;

    // 添加优先级属性
    add_attr(&req.nh, sizeof(req), FRA_PRIORITY, &priority, sizeof(priority));

    // 添加路由表属性
    add_attr(&req.nh, sizeof(req), FRA_TABLE, &table, sizeof(table));

    // 发送 netlink 请求
    send_netlink_request(&req.nh);
}

// 调用示例：添加优先级3、路由表eth1的规则
//add_rule_table_priority(1001, 3);  // 假设 eth1 对应 table ID 1001

static void add_main_rule(int pref, int family){
    struct {
        struct nlmsghdr nh;
        struct rtmsg rt;
        char buf[256];
    } req;

    memset(&req, 0, sizeof(req));
    
    // 初始化消息头
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nh.nlmsg_type = RTM_NEWRULE;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;

    // 配置规则参数
    req.rt.rtm_family = family;    // AF_INET 或 AF_INET6
    req.rt.rtm_protocol = RTPROT_BOOT;
    req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.rt.rtm_type = RTN_UNICAST;

    // 添加优先级属性
    add_attr(&req.nh, sizeof(req), FRA_PRIORITY, &pref, sizeof(pref));

    // // 添加源地址（0.0.0.0/0 或 ::/0 表示 all）
    // if (family == AF_INET) {
    //     struct in_addr any_addr = { INADDR_ANY };
    //     add_attr(&req.nh, sizeof(req), FRA_SRC, &any_addr, sizeof(any_addr));
    // } else if (family == AF_INET6) {
    //     struct in6_addr any_addr = IN6ADDR_ANY_INIT;
    //     add_attr(&req.nh, sizeof(req), FRA_SRC, &any_addr, sizeof(any_addr));
    // }

    // // 添加源地址前缀长度（0 表示 /0）
    // int src_len = 0;
    // add_attr(&req.nh, sizeof(req), FRA_SRC_LEN, &src_len, sizeof(src_len));

    // 发送请求
    send_netlink_request(&req.nh);
}

// 调用示例：添加优先级1的规则
//add_main_rule(1);


//update the main-route-table:
/*
	check the item, for some case to update the items's index member.
	return 0 --> update, other for skip 
*/
int update_rt_main(const route_entry_t *item, route_entry_t *items, int index)
{
	/*
	路由表不为255,254和253;接口名称不为空;目的ip为0.0.0.0
	1. 如果gw为 0.0.0.0 --> 直接使用接口名称添加 ip route add default dev eth0 pri 50 table main
	2. 如果gw不为0.0.0.0 --> ip route add default via 192.168.31.1 dev eth0 pri 50 table main
	*/
	int ret = -1;
	char cmd_buf[1024] = {0};

	if (item->rt_id == 255 || item->rt_id == 254 || item->rt_id == 253) {
		return ret;
	}

	//log_message(LOG_INFO,"ifname:%s, Destination: %s, gw_ip:%s\n", item->name, item->des_ip, item->gw_ip);

	if (strcmp(item->des_ip, "0.0.0.0") == 0) {
		if (strcmp(item->gw_ip, "0.0.0.0") == 0) {
			// 1. 如果gw为 0.0.0.0 --> 直接使用接口名称添加 ip route add default dev eth0 pri 50 table main
			snprintf(cmd_buf, sizeof(cmd_buf), "ip route add default dev %s pri %d table main\n", items[index].name, items[index].metric);
			system(cmd_buf);
			log_message(LOG_NOTICE,"insert the dev:%s into main table. cmd=%s\n", items[index].name, cmd_buf);
			ret = 0;
		} else {
			// 2. 如果gw不为0.0.0.0 --> ip route add default via 192.168.31.1 dev eth0 pri 50 table main
			snprintf(cmd_buf, sizeof(cmd_buf), "ip route add default via %s dev %s pri %d table main\n", item->gw_ip, items[index].name, items[index].metric);
			system(cmd_buf);
			strcpy(items[index].gw_ip, item->gw_ip);
			log_message(LOG_NOTICE,"insert the gw_ip:%s into main table. cmd=%s\n", items[index].gw_ip, cmd_buf);
			ret = 0;
		}
		
	} else {
		ret = -2;
	}

}

// 新增路由表获取函数
/**
 * @brief 初始化路由表
 * 
 * @param rt_items 路由条目数组
 * @param rt_len 路由条目数量
 * @param family 地址族（AF_INET或AF_INET6）
 * @return int 成功返回路由条目数量，失败返回-1
 * 
 * 该函数通过netlink获取系统路由表信息，并更新到rt_items数组中。
 */
int init_route_table(route_entry_t *rt_items, int rt_len, int family) 
{
    struct nlmsghdr *nlmsg;
    struct rtmsg *rtm;
    char buf[4096];
    int fd, len;

    // 创建NETLINK socket
    if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
        perror("socket");
        return -1;
    }

    // 构造请求
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req = {
        .nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg)),
        .nlh.nlmsg_type = RTM_GETROUTE,
        .nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
        .g.rtgen_family = AF_UNSPEC,
    };

    // 发送请求
    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        perror("send");
        close(fd);
        return -1;
    }

	// 增加超时设置（在socket创建后立即设置）
	struct timeval tv = {
		.tv_sec = 2,  // 5秒超时
		.tv_usec = 0
	};
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		perror("setsockopt");
		close(fd);
		return -1;
	}

    // 接收响应
	int received = 0;
    int count = 0;
    while (1) {
		len = recv(fd, buf + received, sizeof(buf) - received, 0);
		if (len > 0) {
			received += len;
			// 处理完整报文（可能需要处理粘包）
			
			for (nlmsg = (struct nlmsghdr *)buf; NLMSG_OK(nlmsg, len); nlmsg = NLMSG_NEXT(nlmsg, len)) {
        		if (nlmsg->nlmsg_type == NLMSG_DONE)
            		break;

        		rtm = (struct rtmsg *)NLMSG_DATA(nlmsg);
        		// if (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6)
            	// 	continue;
				//just match the input family
				if (rtm->rtm_family != family)
					continue;

	    	    // 新增详细解析逻辑
    	    	char dst[INET6_ADDRSTRLEN] = {0};
				char src[INET6_ADDRSTRLEN] = {0};
				char gateway[INET6_ADDRSTRLEN] = {0};
				char mask[INET6_ADDRSTRLEN] = {0};
				int ifindex = 0;
				char ifname[IF_NAMESIZE] = "unknow";
				uint32_t table_id = 255;
				uint32_t metric = 0;
				struct rtattr *attr = RTM_RTA(rtm);
				int attr_len = RTM_PAYLOAD(nlmsg);
				// 遍历路由属性
				for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
					switch(attr->rta_type) {
						case RTA_DST:
							inet_ntop(rtm->rtm_family, RTA_DATA(attr), 
									dst, sizeof(dst));
							break;
						case RTA_GATEWAY:
							inet_ntop(rtm->rtm_family, RTA_DATA(attr), 
									gateway, sizeof(gateway));
							break;
						case RTA_PREFSRC:
							// 可选：处理首选源地址
							break;
						case RTA_OIF:
							ifindex = *(int *)RTA_DATA(attr);
							break;
						case RTA_SRC:
							inet_ntop(rtm->rtm_family, RTA_DATA(attr), 
									src, sizeof(src));
							break;
						case RTA_PRIORITY:
						{
							metric = *(uint32_t *)RTA_DATA(attr);
							break;
						}
						case RTA_TABLE:
						{
							table_id = *(uint32_t *)RTA_DATA(attr);
							break;
						}
						default:
							log_message(LOG_INFO,"Unknown attribute type: %d\n", attr->rta_type);
							break;
					}
				}

				// 计算IPv4子网掩码
				if (rtm->rtm_family == AF_INET) {
					uint32_t netmask = 0;
					if (rtm->rtm_dst_len) {
						netmask = htonl(~((1 << (32 - rtm->rtm_dst_len)) - 1));
					}
					inet_ntop(AF_INET, &netmask, mask, sizeof(mask));
				}

				// 打印路由信息
				log_message(LOG_INFO,"\n[Route %d]\n", ++count);
				log_message(LOG_INFO,"\tFamily: %s\n", (rtm->rtm_family == AF_INET) ? "IPv4" : "IPv6");
				log_message(LOG_INFO,"\tDestination: %s/%d\n", dst[0] ? dst : "0.0.0.0", rtm->rtm_dst_len);
				log_message(LOG_INFO,"\tSrc: %s/%d\n", src, rtm->rtm_dst_len);
				log_message(LOG_INFO,"\tPri: %d\n", metric);
				log_message(LOG_INFO,"\ttable_id: %d\n", table_id);
				log_message(LOG_INFO,"\tNetmask: %s\n", mask);
				log_message(LOG_INFO,"\tGateway: %s\n", gateway[0] ? gateway : "0.0.0.0");
				log_message(LOG_INFO,"\tInterface Index: %d (%s)\n\n", ifindex, if_indextoname(ifindex, ifname) ? ifname : "unknown");
				
				//update the rt_entry：
				for (int i = 0; i < rt_len; i++) {
					if (strcmp(rt_items[i].name, ifname) == 0 && rt_items[i].ip_type == rtm->rtm_family) {
						route_entry_t item = {0};
						strcpy(item.name, ifname);
						item.rt_id = table_id;
						item.ip_type = rtm->rtm_family;
						strcpy(item.des_ip, dst[0] ? dst : "0.0.0.0");
						strcpy(item.gw_ip, gateway[0] ? gateway : "0.0.0.0");
						item.metric = metric;
						update_rt_main(&item, rt_items, i);
					}
				}
			}
    	} else {
        	if (len == 0) break; // 连接关闭
        	if (errno == EAGAIN || errno == EWOULDBLOCK) {
            	log_message(LOG_ERR,"Timeout after %d seconds\n", tv.tv_sec);
            	break;
        	}
        	perror("recv error");
        	break;
    	}
    }

    close(fd);
    return count;
}

/*
LOG_EMERG	0	系统不可用
LOG_ALERT	1	需立即行动
LOG_CRIT	2	严重错误
LOG_ERR	3	一般错误
LOG_WARNING	4	警告
LOG_NOTICE	5	重要正常事件（默认级别）
LOG_INFO	6	信息性消息
LOG_DEBUG	7	
*/
void log_message(int priority, const char *format, ...) {
	if (priority > g_log_level) return;

    va_list args;
    va_start(args, format);
    
#ifdef NDEBUG
    vsyslog(priority, format, args);
#else
    vprintf(format, args);
    //fflush(stdout);  // 确保立即输出
#endif
    
    va_end(args);
}