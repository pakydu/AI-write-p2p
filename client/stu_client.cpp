#include <cstdint>
#include <vector>
#include <arpa/inet.h>
#include <string>
#include <iostream>

enum class NatType
{
        OPEN_INTERNET,   // 开放互联网（无NAT）
        FULL_CONE,               // 完全锥型NAT：允许任意外部地址访问映射地址
        RESTRICTED,              // 受限锥型NAT：仅允许已知IP访问（不限端口）
        PORT_RESTRICTED, // 端口受限锥型：要求IP和端口都匹配
        SYMMETRIC,               // 对称型NAT：不同目标生成不同映射
        UNKNOWN                  // 未知类型/检测失败
};

class StunClient {
public:
    struct StunResponse {
        uint32_t mapped_ip;
        uint16_t mapped_port;
        uint8_t binding_type;
    };

    StunResponse query(const std::string& server, int port) {
        int sock = create_socket();
        connect_to_server(sock, server, port);

        std::vector<uint8_t> request = build_request();
        send_request(sock, request);

        return parse_response(receive_response(sock));
    }

    NatType detectNatType(const std::string& server, uint16_t port) {
    // 增加超时和重试机制
    auto query_with_retry = [&](const std::string& srv, uint16_t p) {
        for(int i=0; i<3; ++i) { // 最多重试3次
            try {
                return query(srv, p, 2000);
            } catch(...) {
                if(i == 2) throw; // 最终仍失败则抛出
            }
        }
        throw std::runtime_error("Query failed after retries");
    };

    // 并行测试基础端口
    auto res1 = query_with_retry(server, port);
    auto res2 = query_with_retry(server, port);

	char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &res1.mapped_ip, ip_str, INET_ADDRSTRLEN);
    std::cout << "res1 Public Address: " << ip_str << ":" << res1.mapped_port << std::endl;
	inet_ntop(AF_INET, &res2.mapped_ip, ip_str, INET_ADDRSTRLEN);
    std::cout << "res2 Public Address: " << ip_str << ":" << res2.mapped_port << std::endl;
    
    // 精确判断对称型NAT
    if (res1.mapped_port != res2.mapped_port || res1.mapped_ip != res2.mapped_ip) {
        return NatType::SYMMETRIC;
    }

    // 异步测试不同地址和端口
    try {
        auto res3 = query_with_retry("stun1.l.google.com", 19302); // 使用真实存在的测试服务器
		inet_ntop(AF_INET, &res3.mapped_ip, ip_str, INET_ADDRSTRLEN);
		std::cout << "res3 Public Address: " << ip_str << ":" << res3.mapped_port << std::endl;
        if(res3.mapped_port == res1.mapped_port) {
            return NatType::FULL_CONE;
        }
    } catch(...) {
        // 精确捕获特定异常类型
        try {
            auto res4 = query_with_retry(server, port+1);
            return (res4.mapped_port == res1.mapped_port) ? 
                NatType::RESTRICTED : NatType::PORT_RESTRICTED;
        } catch(const std::exception& e) {
            // 添加详细日志
            std::cerr << "Final test failed: " << e.what() << std::endl;
        }
    }
    
    return NatType::UNKNOWN;
}

private:
    static const uint16_t BINDING_REQUEST = 0x0001;
    static const uint32_t MAGIC_COOKIE = 0x2112A442;

    int create_socket() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        // 设置socket选项
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        return sock;
    }

    void connect_to_server(int sock, const std::string& server, int port) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, server.c_str(), &addr.sin_addr);

        connect(sock, (sockaddr*)&addr, sizeof(addr));
    }

    std::vector<uint8_t> build_request() {
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

    void send_request(int sock, const std::vector<uint8_t>& data) {
        send(sock, data.data(), data.size(), 0);
    }

    std::vector<uint8_t> receive_response(int sock) {
        std::vector<uint8_t> buffer(512);
        sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t len = recvfrom(sock, buffer.data(), buffer.size(), 0,
                              (sockaddr*)&from, &from_len);
        buffer.resize(len);
        return buffer;
    }

    StunResponse parse_response(const std::vector<uint8_t>& data) {
        StunResponse res{};
        // 解析MAPPED-ADDRESS属性
        size_t pos = 20; // 跳过STUN头
        while(pos < data.size()) {
            uint16_t attr_type = ntohs(*reinterpret_cast<const uint16_t*>(&data[pos]));
            uint16_t attr_len = ntohs(*reinterpret_cast<const uint16_t*>(&data[pos+2]));

            if(attr_type == 0x0020) { // MAPPED-ADDRESS
                res.mapped_port = (htons(*reinterpret_cast<const uint16_t*>(&data[pos+6]))^ (MAGIC_COOKIE >> 16));
                res.mapped_ip = ntohl(htonl(*reinterpret_cast<const uint32_t*>(&data[pos+8]))^ (MAGIC_COOKIE));
                break;
            }
            pos += 4 + attr_len;
        }
        return res;
    }
};


int main(int argc, char** argv) {
    uint16_t port = 3478; // 默认STUN端口
        StunClient client;
        auto response = client.query(argv[1], port);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &response.mapped_ip, ip_str, INET_ADDRSTRLEN);
        std::cout << "Public Address: " << ip_str << ":" << response.mapped_port << std::endl;
        auto natType = client.detectNatType(argv[1], 3478);
    std::cout << "NAT Type: ";
    switch(natType) {
        case NatType::OPEN_INTERNET: std::cout << "Open Internet"; break;
        case NatType::FULL_CONE: std::cout << "Full Cone"; break;
        case NatType::RESTRICTED: std::cout << "Restricted Cone"; break;
        case NatType::PORT_RESTRICTED: std::cout << "Port Restricted"; break;
        case NatType::SYMMETRIC: std::cout << "Symmetric"; break;
        default: std::cout << "Unknown";
    }
    std::cout << std::endl;
    return 0;
}

