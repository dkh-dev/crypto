'use strict'

const crypto = require('crypto')

const promisify = func => (...args) => new Promise((resolve, reject) => {
    func(...args, (error, value) => {
        if (error) {
            reject(error)
        } else {
            resolve(value)
        }
    })
})

const randomBytes = promisify(crypto.randomBytes)

const sha256 = data => crypto
    .createHash('sha256')
    .update(data)
    .digest()

const hmac = {
    sha256(data, key) {
        return crypto
            .createHmac('sha256', key)
            .update(data)
            .digest()
    },
}

const scrypt = promisify(crypto.scrypt)

scrypt.hashiv = async (data, password, iv) => {
    const N = iv.readUInt8(0) ** 2
    const r = iv.readUInt8(1)
    const p = iv.readUInt8(2)

    const key = await scrypt(password, iv, 32, { N, r, p, maxmem: 256 * N * r })

    return Buffer.concat([ iv, hmac.sha256(data, key) ])
}

scrypt.hash = async (data, password, options = {}) => {
    const { N = 16384, r = 8, p = 1 } = options

    const iv = Buffer.alloc(35)
    const salt = await randomBytes(32)

    iv.writeUInt8(N ** (1 / 2))
    iv.writeUInt8(r, 1)
    iv.writeUInt8(p, 2)
    salt.copy(iv, 3)

    return scrypt.hashiv(data, password, iv)
}

scrypt.verify = async (data, password, hash) => {
    const buffer = Buffer.from(hash, 'base64')
    const iv = buffer.slice(0, 35)

    return buffer.equals(await scrypt.hashiv(data, password, iv))
}

const aes256 = {
    async encrypt(data, password) {
        const salt = await randomBytes(16)
        const key = scrypt(password, salt, 32)
        const iv = await randomBytes(16)
        const cipher = crypto.createCipheriv('aes-256-gcm', await key, iv)

        const encrypted = Buffer.concat([
            cipher.update(data),
            cipher.final(),
        ])

        const tag = cipher.getAuthTag()

        return Buffer.concat([ salt, iv, tag, encrypted ])
    },

    async decrypt(data, password) {
        const buffer = Buffer.from(data, 'base64')
        const salt = buffer.slice(0, 16)
        const key = scrypt(password, salt, 32)
        const iv = buffer.slice(16, 32)
        const tag = buffer.slice(32, 48)
        const encrypted = buffer.slice(48)
        const decipher = crypto.createDecipheriv('aes-256-gcm', await key, iv)

        decipher.setAuthTag(tag)

        return Buffer.concat([
            decipher.update(encrypted, 'binary'),
            decipher.final(),
        ])
    },
}

module.exports = {
    randomBytes,
    sha256,
    hmac,
    scrypt,
    aes256,
}
