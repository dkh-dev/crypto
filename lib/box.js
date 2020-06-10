'use strict'

const crypto = require('crypto')

const { encrypt, decrypt } = require('./aes256')
const randomBytes = require('./random-bytes')


const BOX_DEFAULT_AES256_KEY_SIZE = 32

const BOX_DEFAULT_RSA_PADDING = crypto.constants.RSA_PKCS1_OAEP_PADDING

const BOX_DEFAULT_RSA_OAEP_HASH = 'sha1'

const BOX_DEFAULT_RSA_OPTIONS = {
  padding: BOX_DEFAULT_RSA_PADDING,
  oaepHash: BOX_DEFAULT_RSA_OAEP_HASH,
}


// these methods are exported for user convenience
const { createPublicKey } = crypto


/**
 * Supports RSA only.
 * @param {(string|Buffer|PrivateKeyInput)} key
 */
const createPrivateKey = key => {
  const privateKey = crypto.createPrivateKey(key)

  // a silly way to get rsa key size
  // until node exposes keyObject.params or keyObject.fields
  privateKey.params = {
    modulusLength: crypto.publicEncrypt(privateKey, Buffer.alloc(0)).length * 8,
  }

  return privateKey
}

/**
 * @param {KeyObject} key Public or private key
 * @param {(string|Buffer|TypedArray|DataView)} data
 * @param {(Buffer|TypedArray|DataView)} [aad]
 */
const seal = async (key, data, aad) => {
  const secret = await randomBytes(BOX_DEFAULT_AES256_KEY_SIZE)
  const encrypted = await encrypt(secret, data, aad)

  const options = { ...BOX_DEFAULT_RSA_OPTIONS, key }
  const encryptedKey = crypto.publicEncrypt(options, secret)

  return Buffer.concat([ encryptedKey, encrypted ])
}

/**
 * @param {KeyObject} key Private key
 * @param {Buffer} buffer
 * @param {(Buffer|TypedArray|DataView)} [aad]
 */
const open = (key, buffer, aad) => {
  const size = key.params.modulusLength / 8
  const encryptedKey = buffer.slice(0, size)

  const options = { ...BOX_DEFAULT_RSA_OPTIONS, key }
  const secret = crypto.privateDecrypt(options, encryptedKey)

  const encrypted = buffer.slice(size)

  return decrypt(secret, encrypted, aad)
}

/**
 * Note that this module uses the synchronous version of RSA encryption.
 * Using `seal()` and `open()` might cause bottlenecks and make the application
 *   susceptible to DOS attack.
 */
module.exports = {
  BOX_DEFAULT_AES256_KEY_SIZE,
  BOX_DEFAULT_RSA_PADDING,
  BOX_DEFAULT_RSA_OAEP_HASH,
  BOX_DEFAULT_RSA_OPTIONS,
  createPrivateKey,
  createPublicKey,
  seal,
  open,
}
