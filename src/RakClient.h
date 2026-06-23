#pragma once

#include <napi.h>

#include <queue>

#include "RakPeerInterface.h"
#include "Socks5Proxy.h"
#include "Util.h"

class RakClient : public Napi::ObjectWrap<RakClient> {
   private:
    RakNet::RakPeerInterface* client = nullptr;
    Napi::Function connectionCallback;
    Napi::Function packetCallback;
    std::string hostname;
    int port = 0;
    RakNet::SystemAddress conAddr;
    TsfnContext* context = nullptr;
    std::mutex packetMutex;
    std::queue<JSPacket*> packet_queue;
    int protocolVersion = -1;

    // Optional SOCKS5 UDP proxy (UDP ASSOCIATE). When useProxy is set, all of
    // RakNet's UDP traffic is routed through the proxy via a SocketLayerOverride.
    bool useProxy = false;
    std::string proxyHost;
    unsigned short proxyPort = 0;
    std::string proxyUser;
    std::string proxyPass;
    Socks5Proxy* proxy = nullptr;

   public:
    static Napi::Object Initialize(Napi::Env& env, Napi::Object& target);
    // Constructor
    RakClient(const Napi::CallbackInfo& info);
    void Setup();
    // Establishes the SOCKS5 association and installs the socket override.
    // Returns false on failure, writing a reason into errorOut.
    bool ApplyProxy(std::string& errorOut);
    // RAKNET LOOP
    void RunLoop();
    // Listen for packets (e.g. ping or encapsulated)
    Napi::Value Listen(const Napi::CallbackInfo& info);
    // Start connection
    void Connect(const Napi::CallbackInfo& info);
    // Ping
    void Ping(const Napi::CallbackInfo& info);
    // Send an Encapsulated raknet packet
    Napi::Value SendEncapsulated(const Napi::CallbackInfo& info);
    void Close(const Napi::CallbackInfo& info);
    void Close();
    // Called by garbage collector, we don't have to worry about it
    ~RakClient() {
        if (client) {
            client->Shutdown(300);
            RakNet::RakPeerInterface::DestroyInstance(client);
            client = nullptr;
        }
        // Safe to free the override now that the RakNet update thread is stopped.
        if (proxy) {
            delete proxy;
            proxy = nullptr;
        }
    }
};