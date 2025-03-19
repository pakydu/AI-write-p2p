
# 编译说明
## 编译cJosn libaray

## 编译rt_monitor
	mkdir build && cd build
	cmake .. -DCMAKE_TOOLCHAIN_FILE=../toolchain-arm64.cmake -DCMAKE_BUILD_TYPE=Release
	make


# Linux 路由侦测规则

## 根据上面的数据定义我们的结构体：
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


## 配置文件：
提高main 和 default 在rule列表的优先级，使数据优先使用它们进行路由引流
{
	"desc":"用于配置android的路由规则优先级。比如有线网络>wifi>5G",
	"rt_rules":     [{
                        "name": "main",
                        "id":   254,
                        "priority":     100
                }, {
                        "name": "default",
                        "id":   253,
                        "priority":     101
                }],
        "entries":      [{
                        "name": "eth0",
                        "metric":       50,
                        "mac_type":     1,
                        "ip_type":      4
                }, {
                        "name": "eth1",
                        "metric":       51,
                        "mac_type":     1,
                        "ip_type":      4
                }, {
                        "name": "wlan0",
                        "metric":       100,
                        "mac_type":     2,
                        "ip_type":      4
                }, {
                        "name": "sipa_eth0",
                        "metric":       150,
                        "mac_type":     3,
                        "ip_type":      4
                }]
}
## linux 监测规程（以太网）：路由表不为255,254和253;接口名称不为空;目的ip为0.0.0.0
1. 如果gw为 0.0.0.0 --> 直接使用接口名称添加 ip route add default dev eth0 pri 50 table main
2. 如果gw不为0.0.0.0 --> ip route add default via 192.168.31.1 dev eth0 pri 50 table main

## linux 监测规程（wifi）：路由表不为255,254和253;接口名称不为空;目的ip为0.0.0.0
1. 如果gw为 0.0.0.0 --> 直接使用接口名称添加 ip route add default dev wlan0 pri 100 table main
2. 如果gw不为0.0.0.0 --> ip route add default via 192.168.2.1 dev wlan0 pri 100 table main

## linux 监测规程（5G接口）： 路由表不为255,254和253;接口名称不为空;目的ip为0.0.0.0
1. 如果gw为 0.0.0.0 --> 直接使用接口名称添加 ip route add default dev sipa_eth0 proto static scopelink mtu 1500 pri 150 table main
2. 如果gw不为0.0.0.0 --> ip route add default via 192.168.31.1 dev sipa_eth0 proto static pri 150 table main



# android 路由规则

inspur-itgw:/home/android # ip rule
0:      from all lookup local
100:    from all lookup main
101:    from all lookup default
1004:   from 172.17.0.0/16 lookup eth0
1004:   from all to 172.17.0.0/16 lookup eth0
10000:  from all fwmark 0xc0000/0xd0000 lookup legacy_system
11000:  from all iif lo oif dummy0 uidrange 0-0 lookup dummy0
11000:  from all iif lo oif sipa_eth0 uidrange 0-0 lookup sipa_eth0
11000:  from all iif lo oif eth0 uidrange 0-0 lookup eth0
16000:  from all fwmark 0x10063/0x1ffff iif lo lookup local_network
16000:  from all fwmark 0x10064/0x1ffff iif lo lookup sipa_eth0
16000:  from all fwmark 0x10065/0x1ffff iif lo lookup eth0
17000:  from all iif lo oif dummy0 lookup dummy0
17000:  from all iif lo oif sipa_eth0 lookup sipa_eth0
17000:  from all iif lo oif eth0 lookup eth0
18000:  from all fwmark 0x0/0x10000 lookup legacy_system
19000:  from all fwmark 0x0/0x10000 lookup legacy_network
20000:  from all fwmark 0x0/0x10000 lookup local_network
23000:  from all fwmark 0x64/0x1ffff iif lo lookup sipa_eth0
23000:  from all fwmark 0x65/0x1ffff iif lo lookup eth0
31000:  from all fwmark 0x0/0xffff iif lo lookup sipa_eth0
32000:  from all unreachable

inspur-itgw:/home/android # ip route show table main
default via 10.180.146.254 dev eth0 metric 50
default dev sipa_eth0 scope link metric 150
10.0.0.0/8 dev sipa_eth0 proto kernel scope link src 10.154.55.231
10.180.146.0/24 dev eth0 proto kernel scope link src 10.180.146.66
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
192.168.32.0/24 dev br-lan proto kernel scope link src 192.168.32.1


inspur-itgw:/home/android #ip route show table sipa_eth0                                                  <
default dev sipa_eth0 proto static scope link mtu 1400
10.154.55.231 dev sipa_eth0 proto static scope link

# netlink 操作网络的类型：
1. socket 类型 （socket(AF_NETLINK, SOCK_RAW, xxx);）
可以到/include/uapi/linux/netlink.h头文件查看详细定义
   1.1.NETLINK_ROUTE
	NETLINK_ROUTE 不仅用于处理路由信息，还涵盖了与网络接口相关的地址配置（如添加、删除或修改IP地址）等。
   
   1.2. NETLINK_FIREWALL
   用于防火墙相关的事件通知（已废弃）。
   
   1.3. NETLINK_SOCK_DIAG
   用于套接字诊断，可以查询TCP/UDP等协议的连接状态。
   1.4. NETLINK_XFRM
   用于IPSec策略和状态管理。
   1.5. NETLINK_SELINUX
   用于SELinux事件的通知。
   1.6. NETLINK_ISCSI
   用于iSCSI协议的相关通信。
   1.7. NETLINK_AUDIT
   用于审计子系统的事件通知。
   1.8. NETLINK_FIB_LOOKUP
   用于FIB（Forwarding Information Base）查找请求。
   1.9. NETLINK_CONNECTOR
   通用通知机制，用于内核与用户空间之间的通信。
   1.10. NETLINK_NETFILTER
   用于netfilter框架的事件通知，例如iptables规则变化。
   1.11. NETLINK_IP6_FW
   用于IPv6防火墙事件通知（已废弃）。
   1.12. NETLINK_DNRTMSG
   用于DECnet路由消息。
   1.13. NETLINK_KOBJECT_UEVENT
   用于内核对象的用户空间事件通知。
   1.14. NETLINK_GENERIC
   通用Netlink类型，允许自定义消息格式和协议。
   1.15. NETLINK_SCSITRANSPORT
   用于SCSI传输层通信。
   1.16. NETLINK_RDMA
   用于RDMA（远程直接内存访问）相关通信。

2.  Netlink 协议中，nlmsg_type 定义了消息的类型，用于指示 Netlink 消息的具体操作
2.1. 链路（Link）相关类型
这些类型用于处理网络接口（链路）的创建、删除和修改。

RTM_NEWLINK: 创建一个新的网络接口。
RTM_DELLINK: 删除一个网络接口。
RTM_GETLINK: 获取网络接口的信息。
RTM_SETLINK: 修改现有网络接口的属性。
2.2. 地址（Address）相关类型
这些类型用于处理 IP 地址的添加、删除和查询。

RTM_NEWADDR: 添加一个新的 IP 地址到指定的网络接口。（如你在代码中使用的）
RTM_DELADDR: 从指定的网络接口删除一个 IP 地址。
RTM_GETADDR: 获取指定网络接口的 IP 地址信息。
2.3. 路由（Route）相关类型
这些类型用于处理路由表条目的添加、删除和查询。

RTM_NEWROUTE: 添加一个新的路由条目到路由表。
RTM_DELROUTE: 从路由表中删除一个路由条目。
RTM_GETROUTE: 获取路由表中的路由条目。
2.4. 规则（Rule）相关类型
这些类型用于处理路由规则的添加、删除和查询。

RTM_NEWRULE: 添加一个新的路由规则。
RTM_DELRULE: 删除一个路由规则。
RTM_GETRULE: 获取路由规则。
2.5. 邻居（Neighbor/ARP）相关类型
这些类型用于处理邻居表（如 ARP 表）的管理。

RTM_NEWNEIGH: 添加一个新的邻居条目。
RTM_DELNEIGH: 删除一个邻居条目。
RTM_GETNEIGH: 获取邻居表中的条目。
2.6. QoS 和流量控制（TC）相关类型
这些类型用于处理 QoS 和流量控制的相关配置。

RTM_NEWQDISC: 添加一个新的队列调度器。
RTM_DELQDISC: 删除一个队列调度器。
RTM_GETQDISC: 获取队列调度器的信息。
RTM_NEWTCLASS: 添加一个新的流量类。
RTM_DELTCLASS: 删除一个流量类。
RTM_GETTCLASS: 获取流量类的信息。
RTM_NEWTFILTER: 添加一个新的过滤器。
RTM_DELTFILTER: 删除一个过滤器。
RTM_GETTFILTER: 获取过滤器的信息。
2.7. 其他类型
NLMSG_NOOP: 空操作，表示消息被忽略。
NLMSG_ERROR: 表示消息是一个错误响应。
NLMSG_DONE: 表示消息序列结束。


——————————————————————————————————————————————————————————————————————————————

# AI 生成信息
这个项目包含两个子项目：`cJson`和`rt_monitor`。下面分别对这两个子项目进行分析：

### cJson
`cJson` 是一个用于解析和生成JSON数据的C语言库。它提供了一系列的API，使得开发者可以轻松地在C语言中处理JSON数据。从代码结构和内容可以看出，该库支持JSON数据的基本操作，如创建、解析、修改和打印JSON对象和数组。

#### 主要特点：
1. **轻量级**：库的大小经过优化，非常适合作为嵌入式设备或对性能有严格要求的应用的组件。
2. **丰富的API**：提供了各种操作JSON数据的函数，如`cJSON_Parse`用于解析JSON字符串，`cJSON_Print`用于将JSON对象转换为字符串等。
3. **支持对象和数组操作**：如`cJSON_GetObjectItem`和`cJSON_GetArrayItem`等函数，可以方便地获取JSON对象中的字段或数组中的元素。

### rt_monitor
`rt_monitor` 是一个用于监控和管理网络路由的程序。它通过解析配置文件，并监听系统中的网络事件（如新路由的添加或删除），动态地调整路由规则，以保证网络数据的最优传输路径。

#### 主要特点：
1. **配置文件管理**：程序支持通过JSON格式的配置文件来管理路由规则，这使得配置更加灵活和易于管理。
2. **动态路由管理**：通过监听系统中的网络事件，动态地调整路由规则，以适应网络环境的变化。
3. **日志记录**：程序支持日志记录功能，可以方便地追踪和调试网络事件处理过程。

### 编译和构建
项目使用CMake作为构建系统，这使得跨平台编译变得非常方便。通过在`build`目录下运行`cmake`和`make`命令，可以轻松地构建项目。

#### 构建步骤：
1. 创建`build`目录并进入该目录。
2. 运行`cmake .. -DCMAKE_TOOLCHAIN_FILE=../toolchain-arm64.cmake`配置构建系统。
3. 运行`make`命令进行构建。

### 结论
`cJson` 和 `rt_monitor` 这两个子项目分别提供了处理JSON数据和管理网络路由的功能，它们可以独立使用，也可以结合使用以满足特定的需求。通过合理的配置和使用，这两个子项目可以为开发者提供强大的功能和灵活性。