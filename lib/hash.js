'use strict'

const { createHash } = require('crypto')

const { stream } = require('./utils/promisify')


const hash = (algorithm, data) => {
  const hash = createHash(algorithm)

  return stream(hash, data)
}

/**
 * SHA256 hash.
 */
const sha256 = data => hash('sha256', data)

module.exports = {
  sha256,
  subtle: {
    hash,
  },
}
