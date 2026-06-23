const fs = require('fs')
const os = require('os')
const { join } = require('path')

module.exports = {
  getPath () {
    const _osVersion = os.release()

    const plat = process.platform
    const arch = process.arch
    const ver = _osVersion.split('.', 1)

    const bpath = `../prebuilds/${plat}-${ver}-${arch}/node-raknet.node`
    return join(__dirname, bpath)
  },

  getFallbackPath () { // try to ignore OS version & load just on plat+arch
    const prebuildsDir = join(__dirname, '../prebuilds/')
    if (!fs.existsSync(prebuildsDir)) return // no prebuilds (e.g. local source build)
    const dirs = fs.readdirSync(prebuildsDir)
    for (const dir of dirs) {
      const [plat, , arch] = dir.split('-')

      if (plat === process.platform && arch === process.arch) {
        return join(__dirname, '../prebuilds/', dir, '/node-raknet.node')
      }
    }
  },

  getPlatformString () {
    const _osVersion = os.release()

    const plat = process.platform
    const arch = process.arch
    const ver = _osVersion.split('.', 1)
    return `${plat}-${ver}-${arch}`
  }
}
