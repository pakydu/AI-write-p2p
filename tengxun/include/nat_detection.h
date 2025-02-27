#pragma once
#include <string>
#include <vector>

/**
 * NAT（网络地址转换）类型枚举
 * 用于描述设备在NAT环境中的网络类型，不同类型影响P2P通信的可行性
 * 穿透策略决策表
	本地NAT类型		对端NAT类型		穿透策略
	OPEN_INTERNET	任意类型		直连对端
	FULL_CONE		SYMMETRIC		中继服务器
	RESTRICTED		RESTRICTED		双向打洞+端口预测
	PORT_RESTRICTED	PORT_RESTRICTED	UDP端口预测+定时保活
	SYMMETRIC		SYMMETRIC		必须使用中继
 */
enum class NatType {
    OPEN_INTERNET,     ///< 开放互联网，设备具有公网IP，无NAT防护
    FULL_CONE,         ///< 全锥形NAT：允许任何外部地址通过映射端口访问内部主机
    RESTRICTED,        ///< 受限锥形NAT：仅允许已通信的外部IP访问映射端口
    PORT_RESTRICTED,   ///< 端口受限锥形NAT：要求外部IP和端口都必须匹配
    SYMMETRIC,         ///< 对称型NAT：不同目标地址会生成不同的端口映射
    UNKNOWN            ///< 未知类型，检测失败或无法识别的NAT类型
};


struct StunResponse {
    std::string server;
    std::string mapped_ip;
    uint16_t mapped_port;
    uint16_t local_port;
};

StunResponse query_stun(const std::string& server, uint16_t port);
NatType detectNatType(const std::string& server, uint16_t port);