'use strict'

const { createHmac } = require('crypto')

const { stream } = require('./utils/promisify')


const hmac = (algorithm, key, data) => {
  const hmac = createHmac(algorithm, key)

  return stream(hmac, data)
}

/**
 * HMAC-SHA256.
 */
const sha256 = (key, data) => hmac('sha256', key, data)

module.exports = {
  sha256,
  subtle: {
    hmac,
  },
}
