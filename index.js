'use strict'

const crypto = require('crypto')

const sha256 = (data, options = {}) => {
    const { encoding = 'hex' } = options

    return crypto
        .createHash('sha256')
        .update(data)
        .digest(encoding)
}

const hmac = {
    sha256(data, secret, options = {}) {
        const { encoding = 'hex' } = options

        return crypto
            .createHmac('sha256', secret)
            .update(data)
            .digest(encoding)
    },
}

const scrypt = (password, salt, keylen) => new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, (error, key) => {
        if (error) {
            reject(error)
        } else {
            resolve(key)
        }
    })
})

const aes256 = {
    async encrypt(data, password, options = {}) {
        const { encoding = 'hex' } = options

        const salt = crypto.randomBytes(16)
        const key = scrypt(password, salt, 32)
        const iv = crypto.randomBytes(16)
        const cipher = crypto.createCipheriv('aes-256-gcm', await key, iv)

        const encrypted = Buffer.concat([
            cipher.update(data, 'utf8'),
            cipher.final(),
        ])

        const tag = cipher.getAuthTag()

        return Buffer.concat([ salt, iv, tag, encrypted ]).toString(encoding)
    },

    async decypt(data, password, options = {}) {
        const { encoding = 'hex' } = options

        const buffer = Buffer.from(data, encoding)
        const salt = buffer.slice(0, 16)
        const key = scrypt(password, salt, 32)
        const iv = buffer.slice(16, 32)
        const tag = buffer.slice(32, 48)
        const encrypted = buffer.slice(48)
        const decipher = crypto.createDecipheriv('aes-256-gcm', await key, iv)

        decipher.setAuthTag(tag)

        return decipher.update(encrypted, 'binary', 'utf8')
            + decipher.final('utf8')
    },
}

module.exports = {
    sha256,
    hmac,
    scrypt,
    aes256,
}
