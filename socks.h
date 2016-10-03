/*

    SOCKS5 Client Library
    Copyright (c) 2016 NuclearC

*/

#pragma once

#ifndef SOCKS_H_
#define SOCKS_H_

#include <iostream>
#include <string>
#include <sstream>
#include <stack>
#include <vector>
#include <chrono>

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fcntl.h>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

namespace socks5cpp {
	class SocksClient
	{
	public:
		enum SocksState
		{
			Open,
			Connecting,
			Closed
		};

		struct SocksUrl
		{
			enum Type
			{
				WS,
				WSS,
				HTTP
			};

			Type type;
			std::string ip;
			unsigned int port;
			uint8_t ipv4[4];
			uint8_t ipv6[16];
		};

	private:
		std::string ip;
		std::string targetIP;

		SocksUrl url;
		SocksUrl targetUrl;
		SocksState state;

		SOCKET sfd;
	public:
		unsigned long long timeoutDuration = 20000; // 20 seconds

		SocksClient(std::string _Ip, std::string _TargetIp);
		~SocksClient();

		SocksClient::SocksUrl scanURL(const std::string _url);

		int connect();
		int sendPacket(const char* _Buffer, const size_t _Size);
		int recvPacket(char* _Buffer, const size_t _Size);
		void destroy();

		const SocksState& getState();
	protected:

	};
} // socks5cpp

#endif // SOCKS_H_