/*

    SOCKS5 Client Library
    Copyright (c) 2016 NuclearC

*/

#include "socks.h"


namespace socks5cpp {

	SocksClient::SocksClient(std::string _Ip, std::string _TargetIp) : 
		ip(_Ip) ,targetIP(_TargetIp)
	{
		url = scanURL(ip);
		targetUrl = scanURL(targetIP);
	}

	SocksClient::~SocksClient()
	{
		destroy();
	}

	SocksClient::SocksUrl SocksClient::scanURL(const std::string _url)
	{
		SocksClient::SocksUrl res;
		const char * url = _url.c_str();
		char ip[256];
		unsigned int port;
		// scan string
		if (sscanf(url, "ws://%19[^:]:%d", ip, &port)) {
			res.ip = ip;
			res.port = port;
			res.type = SocksUrl::Type::WS;
		}
		else if (sscanf(url, "wss://%19[^:]:%d", ip, &port)) {
			res.ip = ip;
			res.port = port;
			res.type = SocksUrl::Type::WSS;
		}
		else if (sscanf(url, "http://%19[^:]:%d", ip, &port)) {
			res.ip = ip;
			res.port = port;
			res.type = SocksUrl::Type::HTTP;
		}
		else if (sscanf(url, "%19[^:]:%d", ip, &port)) {
			res.ip = ip;
			res.port = port;
			res.type = SocksUrl::Type::HTTP;
		}

		sscanf(res.ip.c_str(), "%hu.%hu.%hu.%hu", &res.ipv4[0], &res.ipv4[1],
			&res.ipv4[2], &res.ipv4[3]);

		return res;
	}

	int SocksClient::connect(SOCKET& sfd)
	{
		state = SocksState::Connecting;

		struct addrinfo
			*result = NULL,
			*ptr = NULL,
			hints;
		int iResult;

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		// Resolve the server address and port
		iResult = getaddrinfo(url.ip.c_str(), std::to_string(url.port).c_str(),
			&hints, &result);
		if (iResult != 0) {
			return -1;
		}

		// Attempt to connect to an address until one succeeds
		for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

			// Create a SOCKET for connecting to server
			sfd = ::socket(ptr->ai_family, ptr->ai_socktype,
				ptr->ai_protocol);
			if (sfd == INVALID_SOCKET) {
				return -1;
			}
			// Connect to server.
			iResult = ::connect(sfd, ptr->ai_addr, (int)ptr->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				closesocket(sfd);
				sfd = INVALID_SOCKET;
				continue;
			}

			// put non-blocking mode
			u_long iMode = 1;
			iResult = ioctlsocket(sfd, FIONBIO, &iMode);

			break;
		}

		freeaddrinfo(result);

		if (sfd == INVALID_SOCKET) {
			return -1;
		}

		// Handhake with SOCKS5 proxy
		std::vector<uint8_t> buffer;

		buffer.clear();
		buffer.push_back(0x05); // version
		buffer.push_back(0x01); // method count
		buffer.push_back(0x00); // first method

		::send(sfd, reinterpret_cast<const char*>(buffer.data()), buffer.size(), 0);

		char handshakeBuffer[512];

		do
		{
			iResult = recv(sfd, handshakeBuffer, 512, 0);
			if (iResult > 0)
			{
				switch (handshakeBuffer[1])
				{
				case 0x00:
					break;
				default:
					return -1;
					break;
				}

				break;
			}
		} while (true);

		buffer.clear();
		buffer.push_back(0x05); // version
		buffer.push_back(0x01); // TCP/IP
		buffer.push_back(0x00); // must be 0x00 always
		buffer.push_back(0x01); // IPv4
		buffer.push_back(targetUrl.ipv4[0]);
		buffer.push_back(targetUrl.ipv4[1]);
		buffer.push_back(targetUrl.ipv4[2]);
		buffer.push_back(targetUrl.ipv4[3]);
		buffer.push_back(targetUrl.port >> 8);
		buffer.push_back(targetUrl.port & 0xff);


		::send(sfd, reinterpret_cast<const char*>(buffer.data()), buffer.size(), 0);

		std::chrono::time_point<std::chrono::steady_clock> begin =
			std::chrono::high_resolution_clock::now();
		std::chrono::time_point<std::chrono::steady_clock> end;
		std::chrono::duration<float> duration;
		std::chrono::milliseconds time;

		do
		{
			end = std::chrono::high_resolution_clock::now();
			duration = end - begin;
			time = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
			if (time.count() > timeoutDuration)
			{
				iResult = -2;
				break;
			}

			iResult = recv(sfd, handshakeBuffer, 512, 0);
			if (iResult > 0)
			{
				iResult = handshakeBuffer[1];
				switch (iResult)
				{
				case 0x00:
					state = SocksState::Open;
					break;
				default:
					state = SocksState::Closed;
					break;
				}

				break;
			}
		} while (true);

		return iResult;
	}

	int SocksClient::sendPacket(SOCKET& sfd, const char * _Buffer, const size_t _Size)
	{
		return ::send(sfd, _Buffer, _Size, 0);
	}

	int SocksClient::recvPacket(SOCKET& sfd, char * _Buffer, const size_t _Size)
	{
		return ::recv(sfd, _Buffer, _Size, 0);
	}

	void SocksClient::destroy()
	{
		state = SocksState::Closed;
	}

	const SocksClient::SocksState & SocksClient::getState()
	{
		return state;
	}

} // socks5cpp