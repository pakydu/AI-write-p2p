#include "nat_detection.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <stdexcept>
// 在nat_detection.cpp中添加
#include <random>
#include <cstring>
#include <algorithm>
#include <iostream>

namespace STUN {
    const uint32_t MAGIC_COOKIE = 0x2112A442;
    
    enum MessageType : uint16_t {
        BINDING_REQUEST = 0x0001,
        BINDING_RESPONSE = 0x0101
    };

    enum AttributeType : uint16_t {
        MAPPED_ADDRESS = 0x0001,
        XOR_MAPPED_ADDRESS = 0x0020,
        SOFTWARE = 0x8022,
        ERROR_CODE = 0x0009
    };

#pragma pack(push, 1)
    struct Header {
        uint16_t type;
        uint16_t length;
        uint32_t magic;
        uint8_t transaction_id[12];
    };

    struct Attribute {
        uint16_t type;
        uint16_t length;
        uint8_t value[];
    };
#pragma pack(pop) 
}

std::vector<uint8_t> create_stun_request() {
    using namespace STUN;
    
    std::vector<uint8_t> packet(sizeof(Header));
    Header* header = reinterpret_cast<Header*>(packet.data());
    
    // 生成随机事务ID
    std::random_device rd;
    std::generate_n(header->transaction_id, 12, [&]{ return rd()%256; });
    
    header->type = htons(BINDING_REQUEST);
    header->length = 0;
    header->magic = htonl(MAGIC_COOKIE);
    
    // 添加SOFTWARE属性
    const char software[] = "P2PClient/1.0";
    Attribute* attr = reinterpret_cast<Attribute*>(
        packet.data() + sizeof(Header));
    
    packet.resize(packet.size() + sizeof(Attribute) + sizeof(software));
    attr->type = htons(SOFTWARE);
    attr->length = htons(sizeof(software));
    memcpy(attr->value, software, sizeof(software));
    
    header->length = htons(packet.size() - sizeof(Header));
    return packet;
}
//static const uint16_t BINDING_REQUEST = 0x0001;
//static const uint32_t MAGIC_COOKIE = 0x2112A442;
std::vector<uint8_t> build_request() {
	using namespace STUN;
        std::vector<uint8_t> packet(20);
        // STUN头部
		
        *reinterpret_cast<uint16_t*>(&packet[0]) = htons(BINDING_REQUEST);
        *reinterpret_cast<uint16_t*>(&packet[2]) = htons(0); // Length
        *reinterpret_cast<uint32_t*>(&packet[4]) = htonl(MAGIC_COOKIE);
        // Transaction ID (12 bytes)
        for(int i=8; i<20; ++i) {
            packet[i] = rand() % 256;
        }
        return packet;
}

StunResponse parse_stun_response(const uint8_t* data, size_t len, 
                                const std::string& server) {
    using namespace STUN;
    if(len < sizeof(Header)) throw std::runtime_error("Invalid STUN response");

    
    Header* header = reinterpret_cast<Header*>(const_cast<uint8_t*>(data));
    if(ntohl(header->magic) != MAGIC_COOKIE) {
        throw std::runtime_error("Invalid magic cookie");
    }

    StunResponse res;
    res.server = server;
    
    const uint8_t* ptr = data + sizeof(Header);
    const uint8_t* end = data + len;
    
    while(ptr < end) {
        Attribute* attr = reinterpret_cast<Attribute*>(const_cast<uint8_t*>(ptr));
        uint16_t type = ntohs(attr->type);
        uint16_t length = ntohs(attr->length);
        
        if(type == XOR_MAPPED_ADDRESS && length >= 8) {
            // 解析XOR映射地址
            uint8_t family = *(attr->value + 1);
            if(family == 0x01) { // IPv4
                uint16_t port = ntohs(*reinterpret_cast<const uint16_t*>(attr->value + 2)) 
                              ^ (MAGIC_COOKIE >> 16);
                uint32_t ip = ntohl(*reinterpret_cast<const uint32_t*>(attr->value + 4)) 
                             ^ MAGIC_COOKIE;
                
                res.mapped_port = port;
                res.mapped_ip = std::to_string((ip>>24)&0xFF) + "." +
                               std::to_string((ip>>16)&0xFF) + "." +
                               std::to_string((ip>>8)&0xFF) + "." +
                               std::to_string(ip&0xFF);
            }
        }
        ptr += 4 + ((length + 3) & ~0x3); // 属性4字节头+对齐填充
    }
    return res;
}

StunResponse query_stun(const std::string& server, uint16_t port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) throw std::runtime_error("Socket creation failed");
    
    // 设置超时
    struct timeval tv{2, 0}; // 2秒
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	//printf("%s\n", server.c_str());
	std::cout<<"2:--> "<<server<<std::endl;
    
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
	// 执行DNS查询
	struct addrinfo hints = {}, *res2, *p;
	char port_str[6];
	// 设置查询条件
	snprintf(port_str, sizeof(port_str), "%u", port);
    hints.ai_family = AF_UNSPEC;    // 支持IPv4和IPv6
    // hints.ai_socktype = SOCK_DGRAM; // UDP协议
    // hints.ai_protocol = IPPROTO_UDP;
	hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(server.c_str(), NULL, &hints, &res2);
	printf("status=%d\n", status);
    if (status != 0) {
        throw std::runtime_error(gai_strerror(status));
    }
	//printf("%s\n", server.c_str());
	char ipstr[INET6_ADDRSTRLEN];
	for(p = res2; p != nullptr; p = p->ai_next) {
		//inet_pton(AF_INET, server.c_str(), &serv_addr.sin_addr);
		//serv_addr.sin_addr = ((sockaddr_in*)p->ai_addr)->sin_addr;
		void *addr;
        char *ipver;

        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
			serv_addr.sin_addr = ((sockaddr_in*)p->ai_addr)->sin_addr;
			break;
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("  %s: %s\n", ipver, ipstr);

	}
    
    // 发送请求
    auto request = build_request();//create_stun_request();

    sendto(sock, request.data(), request.size(), 0,
          (sockaddr*)&serv_addr, sizeof(serv_addr));

    
    // 接收响应
    uint8_t buffer[1024];
    sockaddr_in local_addr{};
    socklen_t addr_len = sizeof(local_addr);
    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0,
                          (sockaddr*)&local_addr, &addr_len);
    
    close(sock);
    
    //if(len <= 0) throw std::runtime_error("STUN request timeout");
	// printf("xxxxxxxxx:len=%d\n", len);
	// for(int i = 0; i < len; ++i) {
	// 	printf("%02x ", buffer[i]);
	// }
    
    // 获取本地端口
    StunResponse res = parse_stun_response(buffer, len, server);
    res.local_port = ntohs(local_addr.sin_port);
    
    return res;
}

NatType detectNatType(const std::string& server, uint16_t port) {
    try {
		std::cout<<"000-->"<<server<<std::endl;
        auto res1 = query_stun(server, port);
		std::cout<<"11-->"<<server<<std::endl;
        auto res2 = query_stun(server, port+1);
        
        // 对称型检测
        if(res1.mapped_port != res2.mapped_port) {
            return NatType::SYMMETRIC;
        }
        
        // 测试不同服务器
        auto res3 = query_stun("stun2.l.google.com", 19302);
        if(res3.mapped_port == res1.mapped_port) {
            return NatType::FULL_CONE;
        }
        
        // 测试同服务器不同端口
        auto res4 = query_stun(server, port+2);
        return (res4.mapped_port == res1.mapped_port) ? 
               NatType::RESTRICTED : NatType::PORT_RESTRICTED;
        
    } catch(...) {
        return NatType::UNKNOWN;
    }
}