
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
#include <syslog.h>

#include "handle_ip_route.h"
#include "cJSON.h"


#define DEFAULT_CFG_FILE  "rt_config.json"

static route_entry_t * rt_items = NULL;
static int rt_len = 0;

#ifdef NDEBUG
int g_log_level = LOG_NOTICE;
#else
int g_log_level = LOG_DEBUG;
#endif

// ## 配置文件：
// 提高main 和 default 在rule列表的优先级，使数据优先使用它们进行路由引流
// Note: 30000 is the higher priority than sipa_eth0/eth0 defult rule.
static const char *default_cfg_content = "{\"desc\":\"用于配置android的路由规则优先级。比如有线网络>wifi>5G\", \
	\"rt_rules\":[{\"name\":\"main\",\"id\": 254, \"priority\":30000}, \
		{\"name\":\"default\",\"id\": 253, \"priority\":30001} \
	], \
	\"entries\":[{\"name\":\"eth0\",\"metric\": 50, \"mac_type\":1, \"ip_type\":4}, \
		{\"name\":\"eth1\",\"metric\": 51, \"mac_type\":1, \"ip_type\":4},  \
		{\"name\":\"wlan0\",\"metric\": 100, \"mac_type\":2, \"ip_type\":4},  \
		{\"name\":\"sipa_eth0\",\"metric\": 150, \"mac_type\":3, \"ip_type\":4} \
	]}";

/**
 * @brief 监控网络变化的主函数
 * 
 * 该函数创建并绑定一个netlink套接字，用于监听网络接口、地址和路由的变化。
 * 当接收到相关事件时，会调用相应的处理函数进行处理。
 */
void monitorNetworkChanges() {
    int sock_fd;
    struct sockaddr_nl sa;
    char buffer[NETLINK_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    int len;

    // 创建 netlink 套接字
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock_fd < 0) {
        perror("socket");
        return;
    }

    // 初始化 netlink 地址结构
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
	sa.nl_groups |= RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;

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

        for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            switch (nlh->nlmsg_type) {
                case RTM_NEWLINK:
                case RTM_DELLINK:
                    handle_link_event(nlh);
                    break;
                case RTM_NEWADDR:
                case RTM_DELADDR:
                    handle_addr_event(nlh);
                    break;
                case RTM_NEWROUTE:
                case RTM_DELROUTE:
                    handle_route_event(nlh, rt_items, rt_len);
                    break;
                default:
                    log_message(LOG_INFO,"Unknown message type: %d\n", nlh->nlmsg_type);
                    break;
            }
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
 * 该函数解析命令行参数，加载配置文件，初始化路由表，并启动网络监控。
 */
int main(int argc, char *argv[]) {
    int opt;
    const char *config_file = NULL;

    while ((opt = getopt(argc, argv, "c:")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            default:
                log_message(LOG_WARNING,"Usage: %s -c <config_file>\n", argv[0]);
                return 1;
        }
    }

	//testing:
	// char ip_buf[INET6_ADDRSTRLEN] = {0};
	// if (set_ip_address("docker0", "192.168.1.100", 24) == 0) {
    //     printf("IP address set successfully.\n");
    // } else {
    //     printf("Failed to set IP address.\n");
    // }

    // if (get_interface_ip("docker0", ip_buf, AF_INET)) {
    //     printf("IPv4 Address: %s\n", ip_buf);
    // } else {
    //     printf("Failed to get IPv4 address for enp0s3\n");
    // }

    // if (get_interface_ip("docker0", ip_buf, AF_INET6)) {
    //     printf("IPv6 Address: %s\n", ip_buf);
    // } else {
    //     printf("Failed to get IPv6 address for enp0s3\n");
    // }

	// return 0;


	cJSON *pJson = NULL;
	FILE *fp = NULL;

    if (config_file == NULL) {
        log_message(LOG_NOTICE,"Use the default file config.\n");
		pJson = cJSON_Parse(default_cfg_content);
		if (pJson)
		{
			char *tmp = cJSON_Print(pJson);
			if(tmp)
			{
				log_message(LOG_INFO,"json: %s\n", tmp);
				fp = fopen(DEFAULT_CFG_FILE, "w");
				if (fp)
				{
					fwrite(tmp, strlen(tmp), 1, fp);
					fclose(fp);
				}
				free(tmp);
			}
		}
    } else {
		pJson = json_load_file(config_file);
	}

	if (pJson)
	{
		//next init the cfg
		//step 0: check the log level
		cJSON *pLogLevel = cJSON_GetObjectItem(pJson, "log_level");
		if (pLogLevel)
		{
			g_log_level = cJSON_GetNumberValue(pLogLevel);
		}

		//step 1: check the ip rule
		cJSON *pItems = cJSON_GetObjectItem(pJson, "rt_rules");
		if (pItems)
		{
			rt_len = cJSON_GetArraySize(pItems);
			for(int i=0; i< rt_len; i++) 
			{
				cJSON *item = cJSON_GetArrayItem(pItems, i);
				int id = -1, priority = -1;
				json_int(item, "id", &id);
				json_int(item, "priority", &priority);
				if (id > 0 && priority > 0) {
					add_rule_table_priority(id, priority);
				}
			}
		}

		//step 2: check the route entries
		pItems = cJSON_GetObjectItem(pJson, "entries");
		rt_len = 0;
		if (pItems)
		{
			rt_len = cJSON_GetArraySize(pItems);
			rt_items = (route_entry_t *)malloc(sizeof(route_entry_t) * rt_len);
			memset(rt_items, 0, sizeof(route_entry_t) * rt_len);
			log_message(LOG_INFO,"route array size is %d\n",rt_len);
			for(int i=0; i< rt_len; i++) 
			{
				cJSON *item = cJSON_GetArrayItem(pItems, i);
				json_int(item, "metric", &rt_items[i].metric);
				json_str(item, "name", (char *)&rt_items[i].name, sizeof(rt_items[i].name));
				rt_items[i].rt_id = 254;//just for main table.
				json_int(item, "mac_type", &rt_items[i].mac_type);
				json_int(item, "ip_type", &rt_items[i].ip_type);
				if (rt_items[i].ip_type == 4) //4 --> AF_INET, 6 --> AF_INET6
					rt_items[i].ip_type = AF_INET;
				else
					rt_items[i].ip_type = AF_INET6;
				strcpy(rt_items[i].gw_ip, IPV4_ZERO_STR);
				strcpy(rt_items[i].des_ip, IPV4_ZERO_STR);
			}
		}
		cJSON_Delete(pJson);
	}

	//get the running info
	init_route_table(rt_items, rt_len, AF_INET);
	//

    monitorNetworkChanges();
    return 0;
}
