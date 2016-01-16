'use strict'
const _ = require('underscore')
const mac_pattern = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/

class node {
  constructor (mac_addr) {
    this.mac = mac_addr
    this._dincoming_links = []
    this._doutgoing_links = []
    this.isAP = false
  }

  _isValidAddress (mac) {
    return mac_pattern.exec(mac) !== null && this.mac !== mac
  }

  /*
    Add mac address with which this node talks directly
  */
  dincoming (mac) {
    if (!this._isValidAddress(mac)) return false
    let di = this._dincoming_links
    if (!_.contains(di, mac)) {
      di.push(mac)
      return true
    }
    return false
  }

  /*
    Add mac address with which this node talks directly
  */
  doutgoing (mac) {
    if (!this._isValidAddress(mac)) return false
    let oi = this._doutgoing_links
    if (!_.contains(oi, mac)) {
      oi.push(mac)
      return true
    }
    return false
  }

  set isAP (value) {
    this._AP = value
  }

  get isAP () {
    return this._AP
  }
}

module.exports = node
