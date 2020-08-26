'use strict'

const {
  createPrivateKey: createPrivateKeyObject,
  createPublicKey,
  publicEncrypt,
  privateDecrypt,
  constants: { RSA_PKCS1_OAEP_PADDING },
} = require('crypto')

const { encrypt, decrypt } = require('./aes256')
const { randomBytes } = require('./crypto')


const BOX_DEFAULT_AES256_KEY_SIZE = 32
const BOX_DEFAULT_RSA_PADDING = RSA_PKCS1_OAEP_PADDING
const BOX_DEFAULT_RSA_OAEP_HASH = 'sha1'
const BOX_DEFAULT_RSA_OPTIONS = {
  padding: BOX_DEFAULT_RSA_PADDING,
  oaepHash: BOX_DEFAULT_RSA_OAEP_HASH,
}


/**
 * Creates private key object with `keyObject.params.modulusLength`.
 * Supports RSA only.
 * @param {(string|Buffer|PrivateKeyInput)} key
 */
const createPrivateKey = key => {
  const keyObject = createPrivateKeyObject(key)

  // node #30045 https://github.com/nodejs/node/pull/30045
  // a silly way to get rsa key size until node exposes `keyObject.params`
  keyObject.params = {
    modulusLength: publicEncrypt(keyObject, Buffer.alloc(0)).length * 8,
  }

  return keyObject
}

/**
 * @param {KeyObject} key Public or private key
 * @param {(string|Buffer|TypedArray|DataView)} data
 * @param {(string|Buffer|TypedArray|DataView)} [aad]
 */
const seal = async (key, data, aad) => {
  const secret = await randomBytes(BOX_DEFAULT_AES256_KEY_SIZE)
  const encrypted = await encrypt(secret, data, aad)

  const options = {
    ...BOX_DEFAULT_RSA_OPTIONS,
    key,
  }
  const encryptedKey = publicEncrypt(options, secret)

  return Buffer.concat([ encryptedKey, encrypted ])
}

/**
 * @param {KeyObject} key Private key
 * @param {Buffer} buffer
 * @param {(string|Buffer|TypedArray|DataView)} [aad]
 */
const open = (key, buffer, aad) => {
  const size = key.params.modulusLength / 8
  const encryptedKey = buffer.slice(0, size)
  const encrypted = buffer.slice(size)

  const options = {
    ...BOX_DEFAULT_RSA_OPTIONS,
    key,
  }
  const secret = privateDecrypt(options, encryptedKey)

  return decrypt(secret, encrypted, aad)
}

/**
 * Note that this module uses the synchronous version of RSA encryption.
 * Using `seal()` and `open()` might cause bottlenecks and make the application
 *   susceptible to DOS attack.
 */
module.exports = {
  seal,
  open,
  createPrivateKey,
  createPublicKey,
  constants: {
    BOX_DEFAULT_AES256_KEY_SIZE,
    BOX_DEFAULT_RSA_PADDING,
    BOX_DEFAULT_RSA_OAEP_HASH,
    BOX_DEFAULT_RSA_OPTIONS,
  },
}
