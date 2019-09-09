'use strict'

const test = require('tape')

const crypto = require('..')


const data = 'data'
const secret = 'secret'

const base64 = { encoding: 'base64' }

test('SHA-256', t => {
    t.equal(crypto.sha256(data), `3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7`)

    t.end()
})

test('HMAC', t => {
    t.equal(crypto.hmac.sha256(data, secret), `1b2c16b75bd2a870c114153ccda5bcfca63314bc722fa160d690de133ccbb9db`)
    t.equal(crypto.hmac.sha256(data, secret, base64), `GywWt1vSqHDBFBU8zaW8/KYzFLxyL6Fg1pDeEzzLuds=`)

    t.end()
})

test('AES-256', async t => {
    const encrypted = await crypto.aes256.encrypt(data, secret, base64)
    const decrypted = await crypto.aes256.decypt(encrypted, secret, base64)

    t.equal(decrypted, data)

    t.end()
})
