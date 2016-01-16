'use strict'
const Transform = require('stream').Transform
const PACKET_START = '<packet>'
const PACKET_END = '</packet>'

class Transformer extends Transform {

  constructor (options) {
    super(options)
    this._buffer = ''
  }

  _transform (chunk, encoding, callback) {
    this._buffer += chunk.toString()
    this._processBuffer()
    callback()
  }

  _processBuffer () {
    while (this._processPacket());
  }

  _processPacket () {
    let si = this._buffer.indexOf(PACKET_START)
    let ei = this._buffer.indexOf(PACKET_END)
    if (si === -1 || ei === -1) {
      return false
    }

    /*
      Case like this
      </packet> <packet> ...........
    */
    if (ei < si) {
      this._buffer = this._buffer.substring(si)
      return true // let is check in next round for packet
    }

    var packetData = this._buffer.substring(si, ei + PACKET_END.length)
    this.push(packetData)
    this._buffer = this._buffer.substring(ei + PACKET_END.length)

    return true
  }
}

module.exports = Transformer
