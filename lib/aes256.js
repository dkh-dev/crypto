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


/**
 * @param {(string|Buffer|TypedArray|DataView)} password
 * @param {(string|Buffer|TypedArray|DataView)} data
 */
const encrypt = async (password, data) => {
  const salt = await randomBytes(AES256_DEFAULT_SALT_SIZE)
  const [ iv, keyIv, key ] = await Promise.all([
    // iv is of size 96 bits; fixed
    randomBytes(AES256_IV_SIZE),

    // scrypt iv will be included in the encrypted data so that
    //   the generated key can be backwards compatible
    derivedIv(),
    scrypt(password, salt, AES256_KEY_SIZE),
  ])

  const cipher = crypto.createCipheriv(
    AES256_ALGORITHM,
    key,
    iv,
    AES256_OPTIONS,
  )
  const encrypted = await stream(cipher, data)
  const tag = cipher.getAuthTag()

  const metadata = Uint8Array.from([ keyIv.length, salt.length ])

  return Buffer.concat([
    metadata,
    iv,
    keyIv,
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
 */
const decrypt = async (password, data) => {
  const [ keyIvSize, saltSize ] = bytes.read(data, Array(2).fill(1))
  const sizes = [
    AES256_IV_SIZE,
    keyIvSize,
    saltSize,
    AES256_AUTH_TAG_LENGTH,
  ]
  const [ iv, keyIv, salt, tag, encrypted ] = bytes.split(data, sizes, 2, true)

  const options = derivedOptions(keyIv)
  const key = await scrypt(password, salt, AES256_KEY_SIZE, options)

  const decipher = crypto.createDecipheriv(
    AES256_ALGORITHM,
    key,
    iv,
    AES256_OPTIONS,
  )

  decipher.setAuthTag(tag)

  return stream(decipher, encrypted)
}

module.exports = {
  AES256_KEY_SIZE,
  AES256_IV_SIZE,
  AES256_SALT_SIZE: AES256_DEFAULT_SALT_SIZE,
  AES256_AUTH_TAG_LENGTH,
  AES256_OPTIONS,
  encrypt,
  decrypt,
}
