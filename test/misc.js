/* eslint-env mocha */
const { Server, Client } = require('@mc-zuri/raknet-native')
const { PacketPriority, PacketReliability } = require('../lib/Constants')

class ServerName {
  motd = 'JSRakNet - JS powered RakNet'
  name = 'JSRakNet'
  protocol = 408
  version = '1.16.20'
  players = {
    online: 0,
    max: 5
  }

  gamemode = 'Creative'
  serverId = '0'

  toString () {
    return [
      'MCPE',
      this.motd,
      this.protocol,
      this.version,
      this.players.online,
      this.players.max,
      this.serverId,
      this.name,
      this.gamemode
    ].join(';') + ';'
  }
}

describe('misc test', () => {
  it('works with custom ServerNames', async function () {
    // Dedicated fixed port; previously this used a random port in 19132-19232
    // and never closed the server, which leaked a bound socket into later tests.
    const port = 19233
    const server = new Server('0.0.0.0', port, {
      maxConnections: 3,
      message: Buffer.from('FMCPE;JSRakNet - JS powered RakNet;408;1.16.20;0;5;0;JSRakNet;Creative;')
    })
    server.listen()
    const client = new Client('127.0.0.1', port, 'minecraft')

    client.on('encapsulated', (packet) => {
      client.send(packet.buffer, PacketPriority.HIGH_PRIORITY, PacketReliability.RELIABLE, 0)
    })

    await new Promise((resolve) => {
      server.on('openConnection', (conn) => {
        for (let i = 0; i < 5; i++) {
          const buf = Buffer.alloc(1000)
          for (let j = 0; j < 64; j += 4) buf[j] = j + i
          buf[0] = 0xf0
          conn.send(buf, 1, 0, 0)
        }
        setTimeout(resolve, 300)
      })
      setTimeout(() => {
        client.connect()
        client.ping()
      }, 100)
      setTimeout(resolve, 4000) // safety timeout
    })

    client.close()
    server.close()
    await new Promise((r) => setTimeout(r, 300)) // let sockets fully release
  })
})
