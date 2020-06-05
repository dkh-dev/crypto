'use strict'

const crypto = require('crypto')

const randomBytes = require('./random-bytes')
const { scrypt } = require('./scrypt')
const { stream } = require('./utils/promisify')


const encrypt = async (password, data) => {
  const salt = await randomBytes(32)
  const [ key, iv ] = await Promise.all([
    scrypt(password, salt, 32),
    randomBytes(96),
  ])

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

  const encrypted = await stream(cipher, data)

  const tag = cipher.getAuthTag()

  return Buffer.concat([ salt, iv, tag, encrypted ])
}


const decrypt = async (password, data) => {
  const salt = data.slice(0, 32)
  const iv = data.slice(32, 128)
  const tag = data.slice(128, 144)
  const encrypted = data.slice(144)
  const key = await scrypt(password, salt, 32)

  const decipher = crypto.createDecipheriv('aes-256-gcm', await key, iv)

  decipher.setAuthTag(tag)

  return stream(decipher, encrypted)
}

module.exports = {
  encrypt,
  decrypt,
}
