'use strict'
const spawn = require('child_process').spawn

/*
  TODO: make it work for windows also
*/
function getTsharkLocation () {
  return 'tshark'
}

module.exports = function (option) {
  if (option.filename) {
    return spawn(getTsharkLocation(), ['-r' + option.filename, '-Tpdml', '-n'])
  } else if (option.interface) {
    return spawn(getTsharkLocation(), ['-i' + option.interface, '-Tpdml', '-n'])
  } else {
    throw new Error('currently we only support filename')
  }
}
