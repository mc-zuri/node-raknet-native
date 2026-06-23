#pragma once

#include <string>

#include "RakNetSocket2.h"
#include "RakNetTypes.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET rns_socket_t;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int rns_socket_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#endif

// Routes all of a RakPeer's UDP traffic through a SOCKS5 proxy using the
// UDP ASSOCIATE command (RFC 1928, with optional username/password auth per
// RFC 1929). Implemented as a RakNet::SocketLayerOverride: RakNet calls
// RakNetSendTo()/RakNetRecvFrom() instead of touching its own UDP socket.
//
// Only IPv4 destinations are supported (ATYP 0x01), which covers the typical
// Minecraft Bedrock use case (a single target server).
class Socks5Proxy : public RakNet::SocketLayerOverride {
   public:
    Socks5Proxy();
    ~Socks5Proxy();

    // Performs the TCP handshake + UDP ASSOCIATE with the proxy.
    // Blocks until the association is established (subject to a recv timeout).
    // Returns true on success; on failure writes a human-readable reason into errorOut.
    bool Setup(const std::string& proxyHost, unsigned short proxyPort, const std::string& username,
               const std::string& password, std::string& errorOut);

    // RakNet::SocketLayerOverride
    int RakNetSendTo(const char* data, int length, const RakNet::SystemAddress& systemAddress) override;
    int RakNetRecvFrom(char dataOut[MAXIMUM_MTU_SIZE], RakNet::SystemAddress* senderOut, bool calledFromMainThread) override;

   private:
    rns_socket_t tcpSocket;    // control connection; kept open for the association's lifetime
    rns_socket_t udpSocket;    // relay datagram socket (non-blocking)
    sockaddr_in relayAddr;     // where we send UDP datagrams (BND.ADDR:BND.PORT from the proxy)
    bool ready;

    void CloseSockets();
};
