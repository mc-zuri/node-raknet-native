#include "Socks5Proxy.h"

#include <cstdio>
#include <cstring>
#include <stdint.h>

#include "MTUSize.h"

#ifdef _WIN32
#define RNS_LAST_ERR WSAGetLastError()
#define RNS_WOULDBLOCK WSAEWOULDBLOCK
#else
#include <errno.h>
#include <fcntl.h>
#define RNS_LAST_ERR errno
#define RNS_WOULDBLOCK EWOULDBLOCK
#endif

namespace {

// SOCKS5 UDP request header is 10 bytes for an IPv4 address; leave generous slack.
const int kHeaderMax = 262;

bool SetRecvTimeout(rns_socket_t s, int seconds) {
#ifdef _WIN32
    DWORD tv = (DWORD)seconds * 1000;
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) == 0;
#else
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) == 0;
#endif
}

bool SetNonBlocking(rns_socket_t s) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

void CloseSock(rns_socket_t s) {
    if (s == INVALID_SOCKET) return;
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

// Blocking send of the whole buffer over TCP.
bool SendAll(rns_socket_t s, const char* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, buf + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

// Blocking read of exactly len bytes over TCP (relies on SO_RCVTIMEO to bound the wait).
bool RecvAll(rns_socket_t s, char* buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(s, buf + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

}  // namespace

Socks5Proxy::Socks5Proxy() : tcpSocket(INVALID_SOCKET), udpSocket(INVALID_SOCKET), ready(false) {
    memset(&relayAddr, 0, sizeof(relayAddr));
}

Socks5Proxy::~Socks5Proxy() { CloseSockets(); }

void Socks5Proxy::CloseSockets() {
    CloseSock(tcpSocket);
    CloseSock(udpSocket);
    tcpSocket = INVALID_SOCKET;
    udpSocket = INVALID_SOCKET;
    ready = false;
}

bool Socks5Proxy::Setup(const std::string& proxyHost, unsigned short proxyPort, const std::string& username,
                        const std::string& password, std::string& errorOut) {
    // Resolve the proxy address. RakNet has already initialized winsock via Startup().
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // SOCKS5 control channel over IPv4
    hints.ai_socktype = SOCK_STREAM;

    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%u", (unsigned)proxyPort);

    struct addrinfo* res = nullptr;
    if (getaddrinfo(proxyHost.c_str(), portStr, &hints, &res) != 0 || res == nullptr) {
        errorOut = "could not resolve proxy host " + proxyHost;
        return false;
    }
    sockaddr_in proxyAddr;
    memcpy(&proxyAddr, res->ai_addr, sizeof(sockaddr_in));
    freeaddrinfo(res);

    tcpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcpSocket == INVALID_SOCKET) {
        errorOut = "could not create TCP control socket";
        return false;
    }
    SetRecvTimeout(tcpSocket, 5);

    if (connect(tcpSocket, (sockaddr*)&proxyAddr, sizeof(proxyAddr)) != 0) {
        errorOut = "could not connect to proxy";
        CloseSockets();
        return false;
    }

    const bool useAuth = !username.empty();

    // --- Method negotiation ---
    char greet[4];
    int gl = 0;
    greet[gl++] = 0x05;             // VER
    greet[gl++] = useAuth ? 2 : 1;  // NMETHODS
    greet[gl++] = 0x00;             // NO AUTH
    if (useAuth) greet[gl++] = 0x02;  // USERNAME/PASSWORD
    if (!SendAll(tcpSocket, greet, gl)) {
        errorOut = "failed to send method greeting";
        CloseSockets();
        return false;
    }

    char methodReply[2];
    if (!RecvAll(tcpSocket, methodReply, 2) || (unsigned char)methodReply[0] != 0x05) {
        errorOut = "invalid method-selection reply";
        CloseSockets();
        return false;
    }
    unsigned char method = (unsigned char)methodReply[1];
    if (method == 0xFF) {
        errorOut = "proxy rejected all auth methods";
        CloseSockets();
        return false;
    }

    // --- Username/password sub-negotiation (RFC 1929) ---
    if (method == 0x02) {
        if (!useAuth) {
            errorOut = "proxy requires auth but no credentials were given";
            CloseSockets();
            return false;
        }
        char authReq[1 + 1 + 255 + 1 + 255];
        int al = 0;
        authReq[al++] = 0x01;  // auth version
        authReq[al++] = (char)username.size();
        memcpy(authReq + al, username.data(), username.size());
        al += (int)username.size();
        authReq[al++] = (char)password.size();
        memcpy(authReq + al, password.data(), password.size());
        al += (int)password.size();
        if (!SendAll(tcpSocket, authReq, al)) {
            errorOut = "failed to send credentials";
            CloseSockets();
            return false;
        }
        char authReply[2];
        if (!RecvAll(tcpSocket, authReply, 2) || authReply[1] != 0x00) {
            errorOut = "proxy authentication failed";
            CloseSockets();
            return false;
        }
    } else if (method != 0x00) {
        errorOut = "proxy selected an unsupported auth method";
        CloseSockets();
        return false;
    }

    // --- UDP ASSOCIATE ---
    // We don't yet know our outgoing UDP source, so request with 0.0.0.0:0.
    char assoc[10] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    if (!SendAll(tcpSocket, assoc, 10)) {
        errorOut = "failed to send UDP ASSOCIATE";
        CloseSockets();
        return false;
    }

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    char head[4];
    if (!RecvAll(tcpSocket, head, 4) || (unsigned char)head[0] != 0x05) {
        errorOut = "invalid UDP ASSOCIATE reply";
        CloseSockets();
        return false;
    }
    if ((unsigned char)head[1] != 0x00) {
        errorOut = "proxy refused UDP ASSOCIATE (REP=" + std::to_string((unsigned char)head[1]) + ")";
        CloseSockets();
        return false;
    }

    uint32_t bndAddr = 0;
    uint16_t bndPort = 0;
    unsigned char atyp = (unsigned char)head[3];
    if (atyp == 0x01) {  // IPv4
        char body[6];
        if (!RecvAll(tcpSocket, body, 6)) {
            errorOut = "short UDP ASSOCIATE reply";
            CloseSockets();
            return false;
        }
        memcpy(&bndAddr, body, 4);
        memcpy(&bndPort, body + 4, 2);
    } else if (atyp == 0x03) {  // domain
        char lenByte;
        if (!RecvAll(tcpSocket, &lenByte, 1)) {
            errorOut = "short UDP ASSOCIATE reply (domain)";
            CloseSockets();
            return false;
        }
        char tmp[255 + 2];
        int dlen = (unsigned char)lenByte;
        if (!RecvAll(tcpSocket, tmp, dlen + 2)) {
            errorOut = "short UDP ASSOCIATE reply (domain body)";
            CloseSockets();
            return false;
        }
        memcpy(&bndPort, tmp + dlen, 2);
        // Domain relay address: fall back to the proxy host's IP (resolved above).
        bndAddr = proxyAddr.sin_addr.s_addr;
    } else if (atyp == 0x04) {  // IPv6 relay - unsupported
        errorOut = "proxy returned an IPv6 relay address (unsupported)";
        CloseSockets();
        return false;
    } else {
        errorOut = "unknown ATYP in UDP ASSOCIATE reply";
        CloseSockets();
        return false;
    }

    relayAddr.sin_family = AF_INET;
    relayAddr.sin_port = bndPort;  // already network order
    // If the proxy reports 0.0.0.0 (or a domain), send datagrams to the proxy host itself.
    relayAddr.sin_addr.s_addr = (bndAddr == 0 || atyp == 0x03) ? proxyAddr.sin_addr.s_addr : bndAddr;

    // --- Relay datagram socket ---
    udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSocket == INVALID_SOCKET) {
        errorOut = "could not create UDP relay socket";
        CloseSockets();
        return false;
    }
    sockaddr_in any;
    memset(&any, 0, sizeof(any));
    any.sin_family = AF_INET;
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    any.sin_port = 0;
    if (bind(udpSocket, (sockaddr*)&any, sizeof(any)) != 0) {
        errorOut = "could not bind UDP relay socket";
        CloseSockets();
        return false;
    }
    if (!SetNonBlocking(udpSocket)) {
        errorOut = "could not set UDP relay socket non-blocking";
        CloseSockets();
        return false;
    }

    ready = true;
    return true;
}

int Socks5Proxy::RakNetSendTo(const char* data, int length, const RakNet::SystemAddress& dest) {
    if (!ready) return -1;  // signal RakNet to use its normal send (should not happen once set up)

    char buf[MAXIMUM_MTU_SIZE + kHeaderMax];
    int o = 0;
    buf[o++] = 0x00;  // RSV
    buf[o++] = 0x00;  // RSV
    buf[o++] = 0x00;  // FRAG
    buf[o++] = 0x01;  // ATYP IPv4

    uint32_t a = dest.address.addr4.sin_addr.s_addr;  // network order
    memcpy(buf + o, &a, 4);
    o += 4;
    uint16_t p = dest.GetPortNetworkOrder();
    memcpy(buf + o, &p, 2);
    o += 2;

    if (length > MAXIMUM_MTU_SIZE) length = MAXIMUM_MTU_SIZE;
    memcpy(buf + o, data, length);
    o += length;

    sendto(udpSocket, buf, o, 0, (sockaddr*)&relayAddr, sizeof(relayAddr));
    // Report the payload length to RakNet (any value >= 0 means "handled").
    return length;
}

int Socks5Proxy::RakNetRecvFrom(char dataOut[MAXIMUM_MTU_SIZE], RakNet::SystemAddress* senderOut, bool) {
    if (!ready) return 0;

    char buf[MAXIMUM_MTU_SIZE + kHeaderMax];
    sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    int r = recvfrom(udpSocket, buf, sizeof(buf), 0, (sockaddr*)&from, &fromLen);
    if (r <= 0) return 0;  // would-block / no data / error

    if (r < 10) return 0;     // smaller than the smallest valid header
    if (buf[2] != 0) return 0;  // we don't reassemble fragmented datagrams (FRAG != 0)

    uint32_t srcAddr = 0;
    uint16_t srcPort = 0;
    int o;
    unsigned char atyp = (unsigned char)buf[3];
    if (atyp == 0x01) {  // IPv4
        memcpy(&srcAddr, buf + 4, 4);
        memcpy(&srcPort, buf + 8, 2);
        o = 10;
    } else if (atyp == 0x04) {  // IPv6 source - cannot map to our IPv4 conn, drop
        return 0;
    } else if (atyp == 0x03) {  // domain - unexpected for a relayed reply, drop
        return 0;
    } else {
        return 0;
    }

    int payloadLen = r - o;
    if (payloadLen <= 0 || payloadLen > MAXIMUM_MTU_SIZE) return 0;
    memcpy(dataOut, buf + o, payloadLen);

    RakNet::SystemAddress sa;
    sa.address.addr4.sin_family = AF_INET;
    sa.address.addr4.sin_addr.s_addr = srcAddr;
    sa.SetPortNetworkOrder(srcPort);
    sa.debugPort = ntohs(srcPort);
    sa.systemIndex = (RakNet::SystemIndex)-1;
    *senderOut = sa;

    return payloadLen;
}
