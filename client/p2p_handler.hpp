
#ifndef P2P_HANDLER_H__
#define P2P_HANDLER_H__

#include <iostream>
#include <string>
#include<thread>
#include "stu_client.cpp"

enum class P2PStrategy {
    DIRECT_CONNECT,    // 全锥型NAT直连
    PORT_PREDICTION,   // 端口限制型预测
    RELAY_SERVER       // 对称型使用中继
};

class P2PHandler {
public:
    explicit P2PHandler(StunClient& client) 
        : client(client), strategy(selectStrategy(client.getNatType())) {}

    void startPenetration(const std::string& peerIP, uint16_t peerPort);

private:
	StunClient& client;
	P2PStrategy strategy;
    P2PStrategy selectStrategy(NatType type);

	void establishDirect(const std::string &ip, uint16_t port);
};


#endif // P2P_HANDLER_H__