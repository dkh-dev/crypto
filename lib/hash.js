'use strict'

const crypto = require('crypto')

const { stream } = require('./utils/promisify')


const hash = (algorithm, data) => {
  const hash = crypto.createHash(algorithm)

  return stream(hash, data)
}

/**
 * SHA256 hash.
 */
const sha256 = data => hash('sha256', data)

module.exports = {
  sha256,
}
