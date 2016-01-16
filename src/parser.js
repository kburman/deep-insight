'use strict'
const cheerio = require('cheerio')
const _ = require('underscore')
const NodeGraph = require('./node_graph.js')

class Extractor {
  constructor (options) {
    this._graph = new NodeGraph()
  }

  get nodeGraph () {
    return this._graph
  }

  /*
    packet: @string
  */
  processPacket (packet) {
    let $ = cheerio.load(packet, {xmlMode: true})
    let protos = $('proto[name=frame] > field[name="frame.protocols"]').attr('show')
    var self = this
    _.each(protos.split(':'), function (item) {
      switch (item) {
        case 'wlan':
          self._parseProtoWlan($)
          break
      }
    })
  }

  _parseProtoWlan (packet) {
    let wlan = packet('proto[name=wlan]')
    if (wlan.length === 0) return
    let G = this._graph
    let ra = packet('proto[name=wlan] > field[name="wlan.ra"]').attr('show')
    let da = packet('proto[name=wlan] > field[name="wlan.da"]').attr('show')
    let sa = packet('proto[name=wlan] > field[name="wlan.sa"]').attr('show')
    let ta = packet('proto[name=wlan] > field[name="wlan.ta"]').attr('show')
    let bssid = packet('proto[name=wlan] > field[name="wlan.bssid"]').attr('show')

    _.map([ra, da, sa, ta, bssid], G.createNode.bind(G))

    G.createFlow(sa, ta)
    G.createFlow(ta, ra)
    G.createFlow(ra, da)
    G.makeNodeAP(bssid)
  }
}

module.exports = Extractor
