/* eslint-env mocha */
// End-to-end tests for SOCKS5 UDP proxy support: a RakClient connects to a
// local RakServer *through* a SOCKS5 proxy (UDP ASSOCIATE) and exchanges data.
const path = require('path')
const { Worker } = require('worker_threads')
const { Server, Client } = require('@mc-zuri/raknet-native')
const { PacketPriority, PacketReliability } = require('../lib/Constants')

// Spawn the SOCKS5 proxy in a worker thread (the native handshake blocks the
// calling thread, so the proxy must live on its own event loop).
function spawnProxy (auth) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, 'socks5Proxy.js'), { workerData: { auth } })
    worker.once('message', (addr) => resolve({ ...addr, worker }))
    worker.once('error', reject)
  })
}

function roundTripThroughProxy (proxyOpts, port) {
  return new Promise((resolve, reject) => {
    const message = 'MCPE;raknet-native SOCKS5 test;0;;0;1;0;test;Survival;'
    const server = new Server('0.0.0.0', port, { maxConnections: 3, message: Buffer.from(message) })
    const client = new Client('127.0.0.1', port, { useProxy: proxyOpts })

    let settled = false
    const finish = (err) => {
      if (settled) return
      settled = true
      try { client.close() } catch {}
      try { server.close() } catch {}
      setTimeout(() => (err ? reject(err) : resolve()), 300)
    }

    server.on('encapsulated', ({ buffer }) => {
      // Echo the user packet back to the (single) connected client.
      const con = [...server.connections.values()][0]
      if (con) con.send(buffer, PacketPriority.IMMEDIATE_PRIORITY, PacketReliability.RELIABLE_ORDERED)
    })
    server.listen()

    client.on('connect', () => {
      client.send(Buffer.from([0xf0, 1, 2, 3, 4]), PacketPriority.IMMEDIATE_PRIORITY, PacketReliability.RELIABLE_ORDERED)
    })
    client.on('encapsulated', ({ buffer }) => {
      if (buffer[0] === 0xf0) finish()
      else finish(new Error('unexpected reply payload'))
    })
    client.connect()

    setTimeout(() => finish(new Error('timed out waiting for round-trip through proxy')), 8000)
  })
}

describe('socks5 proxy tests', function () {
  this.timeout(15000)

  it('connects and round-trips through a no-auth SOCKS5 proxy', async function () {
    const proxy = await spawnProxy(null)
    try {
      await roundTripThroughProxy({ host: proxy.host, port: proxy.port }, 19150)
    } finally {
      await proxy.worker.terminate()
    }
  })

  it('connects and round-trips through an authenticated SOCKS5 proxy', async function () {
    const auth = { username: 'user', password: 'secret' }
    const proxy = await spawnProxy(auth)
    try {
      await roundTripThroughProxy({ host: proxy.host, port: proxy.port, ...auth }, 19151)
    } finally {
      await proxy.worker.terminate()
    }
  })
})
