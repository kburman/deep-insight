'use strict'
const _ = require('underscore')
const EventEmitter = require('events')
const NetNode = require('./node_class.js')
const mac_pattern = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/

class NodeGraph extends EventEmitter {
  constructor () {
    super()
    this._graph = []
  }

  get nodeCount () {
    return _.keys(this._graph).length
  }

  _isValidMacAddr (mac_addr) {
    return mac_pattern.exec(mac_addr) !== null
  }

  createNode (mac_addr) {
    if (!this._isValidMacAddr(mac_addr)) return
    if (_.contains(this._graph, mac_addr)) return
    this._graph[mac_addr] = new NetNode(mac_addr)
    this.emit('new:node', {mac_addr: mac_addr})
  }

  /*
    Create link b/w two node assuming that data can flow only from
    src to dst
  */
  createFlow (src_mac_addr, dst_mac_addr) {
    if (!this._isValidMacAddr(src_mac_addr) || !this._isValidMacAddr(dst_mac_addr)) return
    if (src_mac_addr === dst_mac_addr) return // avoid loop
    if (this._graph[dst_mac_addr].dincoming(src_mac_addr)) this.emit('new:link', {src: src_mac_addr, dst: dst_mac_addr})
    this._graph[src_mac_addr].doutgoing(dst_mac_addr)
  }

  makeNodeAP (mac_addr) {
    if (!this._isValidMacAddr(mac_addr)) return
    this._graph[mac_addr].isAP = true
    this.emit('attr:AP', {'mac_addr': mac_addr, isAP: true})
  }
}

module.exports = NodeGraph
