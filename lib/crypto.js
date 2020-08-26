'use strict'

const { randomBytes, scrypt } = require('crypto')

const { callback } = require('./utils/promisify')


module.exports = {
  randomBytes: callback(randomBytes),
  scrypt: callback(scrypt),
}
