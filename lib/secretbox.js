'use strict'

const { encrypt, decrypt } = require('./aes256')
const { randomBytes } = require('./crypto')
const { read } = require('./utils/bytes')


const SECRETBOX_DEFAULT_INPUT_MIN_SIZE = 64

/**
 * Pads data with random bytes.
 * `data` is padded with
 *   random bytes of size `minSize`,
 *   an additional padding of a random size 0-31 bytes, and
 *   1 byte metadata.
 * @private
 */
const pad = async (data, minSize) => {
  const buffer = Buffer.from(data)

  const [ randomByte ] = await randomBytes(1)
  const size = Math.max(minSize - buffer.length, 0) + (randomByte >>> 3)
  const padding = await randomBytes(size)

  const metadata = Uint8Array.from([ size ])

  return Buffer.concat([ buffer, padding, metadata ])
}

/**
 * Strips padding padded by `pad()`.
 * @private
 */
const strip = data => {
  const [ size ] = read(data, [ 1 ], -1)

  return data.slice(0, -(size + 1))
}

/**
 * @param {(string|Buffer|TypedArray|DataView)} password
 * @param {(string|Buffer|TypedArray|DataView)} data
 * @param {(string|Buffer|TypedArray|DataView)} [aad]
 */
const seal = async (password, data, aad) => {
  const buffer = await pad(data, SECRETBOX_DEFAULT_INPUT_MIN_SIZE)

  return encrypt(password, buffer, aad)
}

/**
 * @param {(string|Buffer|TypedArray|DataView)} password
 * @param {(string|Buffer|TypedArray|DataView)} data
 * @param {(string|Buffer|TypedArray|DataView)} [aad]
 */
const open = async (password, data, aad) => {
  const buffer = await decrypt(password, data, aad)

  return strip(buffer)
}

module.exports = {
  seal,
  open,
  constants: {
    SECRETBOX_DEFAULT_INPUT_MIN_SIZE,
  },
}
