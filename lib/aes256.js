'use strict'

const crypto = require('crypto')

const randomBytes = require('./random-bytes')
const { scrypt, derivedIv, derivedOptions } = require('./scrypt')
const { stream } = require('./utils/promisify')
const bytes = require('./utils/bytes')


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
 * @private
 */
const pad = async (data, minSize) => {
  const buffer = Buffer.from(data)

  // data is padded to the size of the min size
  //   with an additional padding of a random size 0-31 bytes
  //   and 1 byte metadata

  const [ randomByte ] = await randomBytes(1)
  const size = Math.max(minSize - buffer.length, 0) + (randomByte >>> 3)
  const padding = await randomBytes(size)

  const metadata = Uint8Array.from([ size ])

  return Buffer.concat([ buffer, padding, metadata ])
}

/**
 * @private
 */
const strip = data => {
  const [ size ] = bytes.read(data, [ 1 ], -1)

  return data.slice(0, -(size + 1))
}

/**
 * @param {(string|Buffer|TypedArray|DataView)} password
 * @param {(string|Buffer|TypedArray|DataView)} data
 * @param {(Buffer|TypedArray|DataView)} [aad]
 */
const encrypt = async (password, data, aad) => {
  const salt = await randomBytes(AES256_DEFAULT_SALT_SIZE)
  const [ iv, kiv, key ] = await Promise.all([
    // iv is of size 96 bits; fixed
    randomBytes(AES256_IV_SIZE),
    // scrypt iv will be included in the encrypted data so that
    //   the generated key can be backwards compatible
    derivedIv(),
    scrypt(password, salt, AES256_KEY_SIZE),
  ])
  const buffer = await pad(data, AES256_DEFAULT_INPUT_MIN_SIZE)

  const cipher = crypto.createCipheriv(
    AES256_ALGORITHM,
    key,
    iv,
    AES256_OPTIONS,
  )

  if (aad) {
    cipher.setAAD(aad)
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
 * @param {(Buffer|TypedArray|DataView)} aad
 */
const decrypt = async (password, data, aad) => {
  const [ kivSize, saltSize ] = bytes.read(data, Array(2).fill(1))
  const sizes = [
    AES256_IV_SIZE,
    kivSize,
    saltSize,
    AES256_AUTH_TAG_LENGTH,
  ]
  const [ iv, kiv, salt, tag, encrypted ] = bytes.split(data, sizes, 2, true)

  const key = await scrypt(password, salt, AES256_KEY_SIZE, derivedOptions(kiv))

  const decipher = crypto.createDecipheriv(
    AES256_ALGORITHM,
    key,
    iv,
    AES256_OPTIONS,
  )

  if (aad) {
    decipher.setAAD(aad)
  }

  decipher.setAuthTag(tag)

  const buffer = await stream(decipher, encrypted)

  return strip(buffer)
}

module.exports = {
  AES256_KEY_SIZE,
  AES256_IV_SIZE,
  AES256_AUTH_TAG_LENGTH,
  AES256_OPTIONS,
  AES256_DEFAULT_SALT_SIZE,
  AES256_DEFAULT_DATA_MIN_SIZE: AES256_DEFAULT_INPUT_MIN_SIZE,
  encrypt,
  decrypt,
}
