#ifndef STUN_SER_HPP__
#define STUN_SER_HPP__
#include <uv.h>
#include <cstdint>
#include <cstring>
#include <iostream>

#include <iostream>
#include <arpa/inet.h>

void print_sockaddr(const sockaddr* addr) {
    if (addr == nullptr) {
        std::cout << "Null address" << std::endl;
        return;
    }

    char ip_str[INET6_ADDRSTRLEN];
    uint16_t port = 0;

    switch (addr->sa_family) {
    case AF_INET: {  // IPv4
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        inet_ntop(AF_INET, &(addr4->sin_addr), ip_str, INET_ADDRSTRLEN);
        port = ntohs(addr4->sin_port);
        std::cout << "IPv4: " << ip_str << ":" << port << std::endl;
        break;
    }
    case AF_INET6: {  // IPv6
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(addr);
        inet_ntop(AF_INET6, &(addr6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
        port = ntohs(addr6->sin6_port);
        std::cout << "IPv6: [" << ip_str << "]:" << port << std::endl;
        break;
    }
    default:
        std::cout << "Unknown address family: " << addr->sa_family << std::endl;
        break;
    }
}


class StunServer {
public:
    StunServer(uint16_t port) : port_(port) {}

    void start();
private:
    uv_udp_t server_;
	uv_udp_t server_2;
    uint16_t port_;
    static const uint32_t MAGIC_COOKIE = 0x2112A442;

    struct StunHeader {
        uint16_t type;
        uint16_t length;
        uint32_t magic;
        uint8_t transaction_id[12];
    };

 static   void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) ;
	
static	void on_receive(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                          const sockaddr* addr, unsigned flags);

 static   void process_packet(uv_udp_t* handle, const char* data, ssize_t len,
                              const sockaddr* client_addr);

 static   void send_response(uv_udp_t* handle, const StunHeader* request_header,
                             const sockaddr* client_addr);
};

#endif // STUN_SER_HPP__