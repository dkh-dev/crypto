'use strict'

const { createCipheriv, createDecipheriv } = require('crypto')

const { randomBytes } = require('./crypto')
const { subtle: { derive, deriveIv, deriveOptions } } = require('./scrypt')
const { stream } = require('./utils/promisify')
const { split, read } = require('./utils/bytes')


const AES256_ALGORITHM = 'aes-256-gcm'
const AES256_KEY_SIZE = 32
const AES256_IV_SIZE = 12
const AES256_AUTH_TAG_LENGTH = 16
const AES256_OPTIONS = {
  authTagLength: AES256_AUTH_TAG_LENGTH,
}
const AES256_DEFAULT_SALT_SIZE = 32
const AES256_DEFAULT_INPUT_MIN_SIZE = 32


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
const encrypt = async (password, data, aad) => {
  const salt = await randomBytes(AES256_DEFAULT_SALT_SIZE)
  const [ iv, kiv, key ] = await Promise.all([
    // iv has a fixed size of 96 bits
    randomBytes(AES256_IV_SIZE),
    // scrypt iv will be included in the encrypted data so that
    //   the generated key can be backwards compatible
    deriveIv(),
    derive(password, salt, AES256_KEY_SIZE),
  ])
  const buffer = await pad(data, AES256_DEFAULT_INPUT_MIN_SIZE)

  const cipher = createCipheriv(AES256_ALGORITHM, key, iv, AES256_OPTIONS)

  if (aad) {
    cipher.setAAD(Buffer.from(aad))
  }

  const encrypted = await stream(cipher, buffer)
  const tag = cipher.getAuthTag()

  const metadata = Uint8Array.from([ kiv.length, salt.length ])

  return Buffer.concat([
    metadata,
    iv,
    kiv,
    salt,
    tag,
    encrypted,
  ])
}

/**
 * Only accepts encrypted data from `aes256.encrypt()`.
 * @see encrypt
 * @param {(string|Buffer|TypedArray|DataView)} password
 * @param {Buffer} data
 * @param {(string|Buffer|TypedArray|DataView)} aad
 */
const decrypt = async (password, data, aad) => {
  const [ kivSize, saltSize ] = read(data, [ 1, 1 ])
  const sizes = [
    AES256_IV_SIZE,
    kivSize,
    saltSize,
    AES256_AUTH_TAG_LENGTH,
  ]
  const [ iv, kiv, salt, tag, encrypted ] = split(data, sizes, 2, true)
  const key = await derive(password, salt, AES256_KEY_SIZE, deriveOptions(kiv))

  const decipher = createDecipheriv(
    AES256_ALGORITHM,
    key,
    iv,
    AES256_OPTIONS,
  )

  if (aad) {
    decipher.setAAD(Buffer.from(aad))
  }

  decipher.setAuthTag(tag)

  const buffer = await stream(decipher, encrypted)

  return strip(buffer)
}

module.exports = {
  encrypt,
  decrypt,
  constants: {
    AES256_KEY_SIZE,
    AES256_IV_SIZE,
    AES256_AUTH_TAG_LENGTH,
    AES256_OPTIONS,
    AES256_DEFAULT_SALT_SIZE,
    AES256_DEFAULT_INPUT_MIN_SIZE,
  },
}
