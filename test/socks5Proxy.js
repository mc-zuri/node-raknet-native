// A minimal SOCKS5 proxy supporting the UDP ASSOCIATE command (RFC 1928) with
// optional username/password auth (RFC 1929). Used by the SOCKS5 proxy tests.
//
// It is designed to run inside a worker_thread so its event loop is independent
// of the client's: raknet-native performs the SOCKS5 handshake synchronously on
// the calling thread, which would otherwise starve a same-thread JS proxy.
const net = require('net')
const dgram = require('dgram')

// Starts the proxy. `auth`, if given, is { username, password } and the proxy
// will require username/password authentication. Calls `onReady({ host, port })`.
function startSocks5Proxy (auth, onReady) {
  const relay = dgram.createSocket('udp4')
  let clientKey = null // address/port of the client side of the relay

  relay.on('message', (msg, rinfo) => {
    const fromClient = clientKey
      ? (rinfo.address === clientKey.address && rinfo.port === clientKey.port)
      : (msg.length >= 10 && msg[0] === 0 && msg[1] === 0 && msg[2] === 0)

    if (fromClient) {
      clientKey = { address: rinfo.address, port: rinfo.port }
      if (msg[3] !== 1) return // only IPv4 ATYP
      const dstAddr = `${msg[4]}.${msg[5]}.${msg[6]}.${msg[7]}`
      const dstPort = msg.readUInt16BE(8)
      relay.send(msg.subarray(10), dstPort, dstAddr) // strip header, forward payload
    } else {
      // reply coming back from a target: wrap with a SOCKS5 UDP header
      if (!clientKey) return
      const ip = rinfo.address.split('.').map(Number)
      const header = Buffer.from([0, 0, 0, 1, ip[0], ip[1], ip[2], ip[3], 0, 0])
      header.writeUInt16BE(rinfo.port, 8)
      relay.send(Buffer.concat([header, msg]), clientKey.port, clientKey.address)
    }
  })

  relay.bind(0, '127.0.0.1', () => {
    const relayPort = relay.address().port
    const tcp = net.createServer((socket) => {
      let stage = 'greeting'
      socket.on('data', (data) => {
        if (stage === 'greeting') {
          // VER NMETHODS METHODS...
          const methods = [...data.subarray(2, 2 + data[1])]
          if (auth) {
            if (!methods.includes(0x02)) { socket.end(Buffer.from([0x05, 0xff])); return }
            socket.write(Buffer.from([0x05, 0x02])) // require username/password
            stage = 'auth'
          } else {
            socket.write(Buffer.from([0x05, 0x00])) // no auth
            stage = 'request'
          }
        } else if (stage === 'auth') {
          // VER ULEN UNAME PLEN PASSWD
          const ulen = data[1]
          const uname = data.subarray(2, 2 + ulen).toString()
          const plen = data[2 + ulen]
          const passwd = data.subarray(3 + ulen, 3 + ulen + plen).toString()
          const ok = uname === auth.username && passwd === auth.password
          socket.write(Buffer.from([0x01, ok ? 0x00 : 0x01]))
          if (!ok) { socket.end(); return }
          stage = 'request'
        } else if (stage === 'request') {
          // VER CMD RSV ATYP DST.ADDR DST.PORT - reply with the relay endpoint
          const reply = Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
          reply.writeUInt16BE(relayPort, 8)
          socket.write(reply)
          stage = 'associated'
        }
      })
      socket.on('error', () => {})
    })
    tcp.listen(0, '127.0.0.1', () => {
      onReady({ host: '127.0.0.1', port: tcp.address().port, close: () => { try { tcp.close() } catch {} try { relay.close() } catch {} } })
    })
  })
}

module.exports = { startSocks5Proxy }

// When run as a worker_thread, start the proxy and post its address back.
// (In a worker, this file is the main module, so detect via isMainThread.)
const { isMainThread, parentPort, workerData } = require('worker_threads')
if (!isMainThread && parentPort) {
  startSocks5Proxy(workerData && workerData.auth, (info) => {
    parentPort.postMessage({ host: info.host, port: info.port })
  })
}
