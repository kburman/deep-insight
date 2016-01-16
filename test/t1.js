'use strict'
const tshark = require('../src/tsharkprocess.js')
const Pdml2packet = require('../src/pdml2packet.js')
const Extractor = require('../src/parser.js')

let preprocessor = new Pdml2packet()
let extractor = new Extractor()
let pcount = 0

tshark({filename: '../caps/train_col.pcapng.gz'}).stdout.pipe(preprocessor)

preprocessor.on('data', (packet) => {
  extractor.processPacket(packet)
  console.log(++pcount, extractor._graph.nodeCount)
})
