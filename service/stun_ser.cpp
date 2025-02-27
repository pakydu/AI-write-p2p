#include <uv.h>
#include <cstdint>
#include <cstring>
#include <iostream>

#include <iostream>
#include <arpa/inet.h>

#include "stun_ser.hpp"
#include "stun.h"

void StunServer::start()
{
        uv_loop_t* loop = uv_default_loop();

        uv_udp_init(loop, &server_);
        sockaddr_in addr;
        uv_ip4_addr("0.0.0.0", port_, &addr);

        uv_udp_bind(&server_, reinterpret_cast<const sockaddr*>(&addr), UV_UDP_REUSEADDR);
        uv_udp_recv_start(&server_, alloc_buffer, on_receive);

		//start the second port:
		uv_udp_init(loop, &server_2);
		sockaddr_in addr2;
        uv_ip4_addr("0.0.0.0", port_+1, &addr2);
		uv_udp_bind(&server_2, reinterpret_cast<const sockaddr*>(&addr2), UV_UDP_REUSEADDR);
        uv_udp_recv_start(&server_2, alloc_buffer, on_receive);

        std::cout << "STUN server running on port " << port_ << std::endl;
        uv_run(loop, UV_RUN_DEFAULT);
}

void StunServer::alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    buf->base = new char[suggested_size];
    buf->len = suggested_size;
}

void StunServer::on_receive(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                          const sockaddr* addr, unsigned flags)
{
        if (nread > 0) {
            print_sockaddr(addr);
            process_packet(handle, buf->base, nread, addr);
        }
        delete[] buf->base;
}

void StunServer::process_packet(uv_udp_t* handle, const char* data, ssize_t len,
                              const sockaddr* client_addr)
{
        if (len < sizeof(StunHeader)) return;

        const StunHeader* header = reinterpret_cast<const StunHeader*>(data);
        if (ntohl(header->magic) != MAGIC_COOKIE) return;

        if (ntohs(header->type) == 0x0001) { // Binding Request
            send_response(handle, header, client_addr);
        }
}

void StunServer::send_response(uv_udp_t* handle, const StunHeader* request_header,
                             const sockaddr* client_addr) {
        // 准备响应缓冲区
        const int response_size = sizeof(StunHeader) + 8 + 8; // Header + XOR-MAPPED-ADDRESS
        char* response = new char[response_size];

        // 填充STUN头
        StunHeader* res_header = reinterpret_cast<StunHeader*>(response);
        res_header->type = htons(0x0101); // Binding Success Response
        res_header->length = htons(8);     // Attribute length
        res_header->magic = htonl(MAGIC_COOKIE);
        memcpy(res_header->transaction_id, request_header->transaction_id, 12);

        // 添加XOR-MAPPED-ADDRESS属性
        char* attr = response + sizeof(StunHeader);
        *reinterpret_cast<uint16_t*>(attr) = htons(0x0020); // XOR-MAPPED-ADDRESS type
        *reinterpret_cast<uint16_t*>(attr+2) = htons(8);    // Length
        *(attr+4) = 0; // Reserved
        *(attr+5) = 0x01; // IPv4 family

        const sockaddr_in* addr_in = reinterpret_cast<const sockaddr_in*>(client_addr);
        uint16_t port = ntohs(addr_in->sin_port) ^ (MAGIC_COOKIE >> 16);
        uint32_t ip = ntohl(addr_in->sin_addr.s_addr) ^ MAGIC_COOKIE;

        *reinterpret_cast<uint16_t*>(attr+6) = htons(port);
        *reinterpret_cast<uint32_t*>(attr+8) = htonl(ip);

        // 发送响应
        uv_buf_t buf = uv_buf_init(response, response_size);
        uv_udp_send_t* send_req = new uv_udp_send_t;

        uv_udp_send(send_req, handle, &buf, 1, client_addr,
                   [](uv_udp_send_t* req, int status) {
                       delete[] reinterpret_cast<char*>(req->data);
                       delete req;
                   });

        send_req->data = response;
}


int main(int argc, char** argv) {
    uint16_t port = 3478; // 默认STUN端口
    if (argc > 1) {
        port = static_cast<uint16_t>(std::stoi(argv[1]));
    }

    StunServer server(port);
    server.start();
    return 0;
}
//g++ -std=c++17 -O3 -o stun_server stun_ser.cpp -luv